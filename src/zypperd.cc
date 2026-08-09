/*---------------------------------------------------------------------------*\
                          ____  _ _ __ _ __  ___ _ _
                         |_ / || | '_ \ '_ \/ -_) '_|
                         /__|\_, | .__/ .__/\___|_|
                             |__/|_|  |_|
\*---------------------------------------------------------------------------*/
/*
 * zypperd - persistent zypper daemon
 *
 * Loads the target and all enabled repositories into the libzypp pool
 * once, then serves zypper commands over a UNIX socket. Each request is
 * handled by a forked child that inherits the loaded pool copy-on-write,
 * so requests cannot poison the resident state and a crashing command
 * cannot take the daemon down. The daemon itself never takes the zypp
 * global lock (readonly hack), so regular zypper keeps working alongside.
 *
 * Read-only allowlisted commands run in-process on the preloaded pool.
 * Mutating commands from a root peer are handled by exec'ing the real
 * /usr/bin/zypper inside the child (real lock, real behavior); anything
 * else is declined and the client falls back to /usr/bin/zypper itself.
 *
 * See zypperd-protocol.h for the wire protocol (binary via zypperc with
 * fd passing, or plain text via e.g. `nc -U`).
 */

#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <zypp-core/base/LogTools.h>
#include <zypp-core/base/LogControl.h>
#include <zypp/ZYppFactory.h>
#include <zypp/zypp_detail/ZYppReadOnlyHack.h>
#include <zypp/sat/Pool.h>
#include <zypp/Target.h>
#include <zypp/base/Backtrace.h>

#include "main.h"
#include "Zypper.h"
#include "Command.h"
#include "repos.h"

#include "callbacks/rpm.h"
#include "callbacks/keyring.h"
#include "callbacks/repo.h"
#include "callbacks/media.h"
#include "callbacks/locks.h"
#include "callbacks/job.h"
#include "utils/messages.h"

#include "zypperd-protocol.h"

#define ZYPPERD_LOG "/var/log/zypperd.log"
#define REAL_ZYPPER "/usr/bin/zypper"

using namespace zypp;

extern ZYpp::Ptr God;

///////////////////////////////////////////////////////////////////
// Signal handling for worker children - copies of the file-static
// handlers in main.cc (they are not exported from zypper_lib).
///////////////////////////////////////////////////////////////////

static const char* exit_requested_once_str = "\nTrying to exit gracefully...\n";
static const char* exit_requested_twice_str = "\nZypper is currently cleaning up, exiting as soon as possible.\n";

static void worker_signal_handler( int /*sig*/ )
{
  // No malloc in here (see main.cc).
  Zypper & zypper( Zypper::instance( true ) );
  if ( zypper.exitRequested() >= 1 ) {
    (void)!write( STDERR_FILENO, exit_requested_twice_str, strlen(exit_requested_twice_str) );
    zypper.requestImmediateExit();
  } else {
    (void)!write( STDERR_FILENO, exit_requested_once_str, strlen(exit_requested_once_str) );
    zypper.requestExit();
  }
}

static bool testPipeFd( int fd_r )
{
  bool ret = true;
  struct pollfd pfd = { fd_r, POLLERR, 0 };
  int pollRes = 0;
  while ( (pollRes = ::poll( &pfd, 1, 0 )) == -1 && errno == EINTR );
  if ( pollRes >= 0 && (pfd.revents & POLLERR) )
    ret = false;
  return ret;
}

static void worker_signal_nopipe( int /*sig*/ )
{
  if ( testPipeFd( STDOUT_FILENO ) && testPipeFd( STDERR_FILENO ) )
  {
    // bsc#1145521 - STDOUT/STDERR are OK. Might be triggered from libcurl.
    ::signal( SIGPIPE, worker_signal_nopipe );
  }
  else
  {
    Zypper & zypper( Zypper::instance( true ) );
    zypper.requestImmediateExit();
  }
}

///////////////////////////////////////////////////////////////////
// Parent signal handling via self-pipe
///////////////////////////////////////////////////////////////////

static int g_selfpipe[2] = { -1, -1 };

static void parent_signal_handler( int sig )
{
  char b = 0;
  switch ( sig )
  {
    case SIGCHLD: b = 'C'; break;
    case SIGTERM:
    case SIGINT:  b = 'T'; break;
    case SIGHUP:  b = 'H'; break;
    default: return;
  }
  int saved = errno;
  (void)!write( g_selfpipe[1], &b, 1 );
  errno = saved;
}

///////////////////////////////////////////////////////////////////
// Small helpers
///////////////////////////////////////////////////////////////////

static time_t nowMono()
{
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return ts.tv_sec;
}

static int sendAll( int fd, const void *buf, size_t len )
{
  const char *p = static_cast<const char *>( buf );
  int patience = 50; // ~5s against a stalled client, then give up
  while ( len )
  {
    ssize_t n = ::send( fd, p, len, MSG_NOSIGNAL );
    if ( n < 0 )
    {
      if ( errno == EINTR )
        continue;
      if ( ( errno == EAGAIN || errno == EWOULDBLOCK ) && --patience > 0 )
      {
        struct pollfd pfd = { fd, POLLOUT, 0 };
        ::poll( &pfd, 1, 100 );
        continue;
      }
      return -1;
    }
    p += n;
    len -= size_t(n);
  }
  return 0;
}

static void sendStatus( int fd, char code, unsigned char arg = 0 )
{
  unsigned char frame[2] = { (unsigned char)code, arg };
  sendAll( fd, frame, 2 );
}

///////////////////////////////////////////////////////////////////
// Request / connection state
///////////////////////////////////////////////////////////////////

struct Conn
{
  int fd = -1;
  enum State { REQUEST, RUNNING } state = REQUEST;
  bool binary = false;
  bool modeKnown = false;
  int clientFds[3] = { -1, -1, -1 };
  std::string buf;
  struct ucred peer = { 0, (uid_t)-1, (gid_t)-1 };
  pid_t child = -1;
  time_t reqDeadline = 0;
  time_t killDeadline = 0;

  std::vector<std::string> argv;
  std::vector<std::string> env;

  void closeClientFds()
  {
    for ( int i = 0; i < 3; ++i )
      if ( clientFds[i] >= 0 )
      { ::close( clientFds[i] ); clientFds[i] = -1; }
  }
};

static std::map<int, Conn> g_conns;          // by connection fd
static std::map<pid_t, int> g_childConn;     // child pid -> connection fd

static int g_listenFd = -1;
static bool g_boundSocketOurselves = false;
static std::string g_socketPath;
static char **g_savedArgv = nullptr;
static unsigned g_maxWorkers = 8;
static bool g_terminating = false;
static bool g_wantReexec = false;

///////////////////////////////////////////////////////////////////
// Pool staleness stamps
///////////////////////////////////////////////////////////////////

struct FileStamp
{
  time_t mtime = 0;
  off_t size = -1;
  ino_t ino = 0;
  bool exists = false;

  bool operator==( const FileStamp &rhs ) const
  { return exists == rhs.exists && mtime == rhs.mtime && size == rhs.size && ino == rhs.ino; }
  bool operator!=( const FileStamp &rhs ) const
  { return !( *this == rhs ); }
};

static FileStamp stampOf( const std::string &path )
{
  FileStamp s;
  struct stat st;
  if ( ::stat( path.c_str(), &st ) == 0 )
  {
    s.exists = true;
    s.mtime = st.st_mtime;
    s.size = st.st_size;
    s.ino = st.st_ino;
  }
  return s;
}

struct PoolStamps
{
  std::string rpmdbPath;                       // best-effort rpmdb file
  FileStamp rpmdb;
  std::map<std::string, FileStamp> repoFiles;  // repos.d + solv cookies
};

static PoolStamps g_warmStamps;

static void stampDir( const std::string &dir, const std::string &suffix,
                      std::map<std::string, FileStamp> &out )
{
  DIR *d = ::opendir( dir.c_str() );
  if ( !d )
    return;
  while ( struct dirent *e = ::readdir( d ) )
  {
    if ( e->d_name[0] == '.' )
      continue;
    std::string p = dir + "/" + e->d_name + suffix;
    out[p] = stampOf( p );
  }
  ::closedir( d );
}

static PoolStamps collectStamps( Zypper &zypper )
{
  PoolStamps ps;

  const std::string root = zypper.config().root_dir == "/" ? "" : zypper.config().root_dir;
  for ( const char *cand : { "/usr/lib/sysimage/rpm/rpmdb.sqlite",
                             "/var/lib/rpm/rpmdb.sqlite",
                             "/usr/lib/sysimage/rpm/Packages.db",
                             "/var/lib/rpm/Packages" } )
  {
    std::string p = root + cand;
    if ( stampOf( p ).exists )
    { ps.rpmdbPath = p; break; }
  }
  if ( !ps.rpmdbPath.empty() )
    ps.rpmdb = stampOf( ps.rpmdbPath );

  const RepoManagerOptions &rmo = zypper.config().rm_options;
  // repo/service definitions: any change invalidates the repo set
  stampDir( rmo.knownReposPath.asString(), "", ps.repoFiles );
  stampDir( rmo.knownServicesPath.asString(), "", ps.repoFiles );
  // per-repo solv caches: <solvcache>/<alias>/cookie changes on rebuild
  stampDir( rmo.repoSolvCachePath.asString(), "/cookie", ps.repoFiles );

  return ps;
}

enum class Staleness { Fresh, RpmDbChanged, ReposChanged };

static Staleness checkStale()
{
  PoolStamps cur = collectStamps( Zypper::instance() );
  if ( cur.repoFiles != g_warmStamps.repoFiles )
    return Staleness::ReposChanged;
  if ( cur.rpmdbPath != g_warmStamps.rpmdbPath || cur.rpmdb != g_warmStamps.rpmdb )
    return Staleness::RpmDbChanged;
  return Staleness::Fresh;
}

///////////////////////////////////////////////////////////////////
// Command classification
///////////////////////////////////////////////////////////////////

enum class Disposition { InProcess, ExecReal, Fallback };

// Commands that only read the pool / configuration.
static bool readOnlyCommand( ZypperCommand::Command c )
{
  switch ( c )
  {
    case ZypperCommand::INFO_e:
    case ZypperCommand::RUG_PATCH_INFO_e:
    case ZypperCommand::RUG_PATTERN_INFO_e:
    case ZypperCommand::RUG_PRODUCT_INFO_e:
    case ZypperCommand::SEARCH_e:
    case ZypperCommand::LIST_REPOS_e:
    case ZypperCommand::LIST_SERVICES_e:
    case ZypperCommand::LIST_PATCHES_e:
    case ZypperCommand::LIST_UPDATES_e:
    case ZypperCommand::PATCH_CHECK_e:
    case ZypperCommand::PATCHES_e:
    case ZypperCommand::PACKAGES_e:
    case ZypperCommand::PATTERNS_e:
    case ZypperCommand::PRODUCTS_e:
    case ZypperCommand::WHAT_PROVIDES_e:
    case ZypperCommand::LIST_LOCKS_e:
    case ZypperCommand::TARGET_OS_e:
    case ZypperCommand::VERSION_CMP_e:
    case ZypperCommand::SYSTEM_ARCHITECTURE_e:
    case ZypperCommand::LOCALES_e:
    case ZypperCommand::HELP_e:
    case ZypperCommand::MOO_e:
      return true;
    default:
      return false;
  }
}

// Global options we understand well enough to run in-process.
// Everything not listed here forces a fallback to the real zypper,
// so --root, --config, --plus-repo, ... and any future option are
// automatically handled correctly without a blocklist.
static bool safeGlobalOption( const std::string &opt, bool &takesArg )
{
  static const std::set<std::string> noArg = {
    "-q", "--quiet", "-v", "--verbose", "-x", "--xmlout", "-t", "--terse",
    "--color", "--no-color", "-A", "--no-abbrev", "-n", "--non-interactive",
    "-i", "--ignore-unknown", "--non-interactive-include-reboot-patches",
    "--no-refresh"
  };
  static const std::set<std::string> withArg = { "-s", "--table-style" };

  takesArg = false;
  if ( noArg.count( opt ) )
    return true;
  if ( withArg.count( opt ) )
  { takesArg = true; return true; }
  if ( opt.rfind( "--table-style=", 0 ) == 0 )
    return true;
  return false;
}

// Per-command arguments that would make a read-only command write files
// as the daemon user (root) on behalf of an unprivileged peer.
static bool deniedCommandArg( ZypperCommand::Command c, const std::string &arg )
{
  if ( c == ZypperCommand::LIST_REPOS_e || c == ZypperCommand::LIST_SERVICES_e )
    return arg == "-e" || arg == "--export" || arg.rfind( "--export=", 0 ) == 0;
  return false;
}

static Disposition classify( const Conn &conn )
{
  // argv[0] is the client's name; scan global options, find the command
  size_t i = 1;
  bool takesArg = false;
  for ( ; i < conn.argv.size(); ++i )
  {
    const std::string &tok = conn.argv[i];
    if ( tok.empty() )
      return Disposition::Fallback;
    if ( tok[0] != '-' )
      break; // the command
    if ( !safeGlobalOption( tok, takesArg ) )
      return Disposition::Fallback;
    if ( takesArg )
      ++i;
  }
  if ( i >= conn.argv.size() )
    return Disposition::Fallback; // no command (prints help/usage): let stock handle it

  ZypperCommand::Command cmd;
  try
  {
    cmd = ZypperCommand::toEnum( conn.argv[i] );
  }
  catch ( const Exception & )
  {
    return Disposition::Fallback; // unknown command
  }

  if ( readOnlyCommand( cmd ) )
  {
    for ( size_t j = i + 1; j < conn.argv.size(); ++j )
      if ( deniedCommandArg( cmd, conn.argv[j] ) )
        return Disposition::Fallback;
    return Disposition::InProcess;
  }

  // Mutating command: only a peer with the daemon's own privileges (root
  // in production) may have the daemon run it, and only in binary mode
  // where the real tty travels along for prompts.
  if ( conn.binary && ( conn.peer.uid == 0 || conn.peer.uid == ::geteuid() ) )
    return Disposition::ExecReal;

  return Disposition::Fallback;
}

///////////////////////////////////////////////////////////////////
// Worker children
///////////////////////////////////////////////////////////////////

[[noreturn]] static void runWorkerChild( Conn &conn, Disposition disp )
{
  ::setpgid( 0, 0 );

  // stdio: binary mode uses the client's own fds, text mode the socket
  if ( conn.binary )
  {
    for ( int i = 0; i < 3; ++i )
      ::dup2( conn.clientFds[i], i );
    conn.closeClientFds();
  }
  else
  {
    int nul = ::open( "/dev/null", O_RDONLY );
    if ( nul >= 0 )
      ::dup2( nul, 0 );
    // the accepted socket is nonblocking; stdio must not be
    ::fcntl( conn.fd, F_SETFL, ::fcntl( conn.fd, F_GETFL ) & ~O_NONBLOCK );
    ::dup2( conn.fd, 1 );
    ::dup2( conn.fd, 2 );
  }
  // Everything above 2 that we still hold is parent business.
  ::close( conn.fd );
  if ( g_listenFd >= 0 )
    ::close( g_listenFd );
  ::close( g_selfpipe[0] );
  ::close( g_selfpipe[1] );

  // client environment (allowlisted at receive time)
  for ( const std::string &kv : conn.env )
  {
    std::string::size_type eq = kv.find( '=' );
    if ( eq != std::string::npos && eq > 0 )
      ::setenv( kv.substr( 0, eq ).c_str(), kv.c_str() + eq + 1, 1 );
  }
  ::setlocale( LC_ALL, "" );

  ::signal( SIGCHLD, SIG_DFL );
  ::signal( SIGHUP, SIG_DFL );
  ::signal( SIGINT, worker_signal_handler );
  ::signal( SIGTERM, worker_signal_handler );
  ::signal( SIGPIPE, worker_signal_nopipe );

  // argv for the command; argv[0] becomes "zypper" for both paths
  std::vector<char *> argv;
  argv.push_back( const_cast<char *>( "zypper" ) );
  bool injectNonInteractive = !conn.binary;
  if ( injectNonInteractive )
    argv.push_back( const_cast<char *>( "--non-interactive" ) );
  for ( size_t i = 1; i < conn.argv.size(); ++i )
    argv.push_back( const_cast<char *>( conn.argv[i].c_str() ) );
  argv.push_back( nullptr );

  if ( disp == Disposition::ExecReal )
  {
    // real zypper takes the real lock and does everything itself
    ::unsetenv( "ZYPP_READONLY_HACK" );
    ::setenv( "PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1 );
    ::execv( REAL_ZYPPER, argv.data() );
    const char msg[] = "zypperd: cannot exec " REAL_ZYPPER "\n";
    (void)!write( STDERR_FILENO, msg, sizeof( msg ) - 1 );
    ::_exit( 127 );
  }

  // Some zypper paths (e.g. Zypper::immediateExit after SIGPIPE) call
  // exit(). In a forked child that must not run the process's static
  // destructors: libzypp's LogThread dtor joins a thread that does not
  // exist after fork (hangs forever), and zypp's TmpDir cleanup would
  // delete the parent's directories. Turn any exit() into _exit().
  ::on_exit( []( int status, void * ) {
    std::cout.flush();
    std::cerr.flush();
    ::fflush( nullptr );
    ::_exit( status );
  }, nullptr );

  int rc = ZYPPER_EXIT_ERR_BUG;
  try
  {
    rc = Zypper::instance().main( int( argv.size() ) - 1, argv.data() );
    if ( !rc )
      rc = Zypper::instance().exitInfoCode();
  }
  catch ( ... )
  {
    rc = ZYPPER_EXIT_ERR_BUG;
  }
  // an OutXML writer emits the closing </stream> from its destructor,
  // which _exit() below would skip
  Zypper::instance().setOutputWriter( nullptr );
  std::cout.flush();
  std::cerr.flush();
  ::fflush( nullptr );
  // _exit: running static dtors here would clean up the parent's tmpdirs
  ::_exit( rc < 0 || rc > 255 ? ZYPPER_EXIT_ERR_BUG : rc );
}

///////////////////////////////////////////////////////////////////
// Request parsing and dispatch
///////////////////////////////////////////////////////////////////

static void closeConn( std::map<int, Conn>::iterator it )
{
  it->second.closeClientFds();
  ::close( it->second.fd );
  if ( it->second.child > 0 )
    g_childConn.erase( it->second.child );
  g_conns.erase( it );
}

static void declineConn( std::map<int, Conn>::iterator it, char code, unsigned char arg = 0 )
{
  Conn &c = it->second;
  if ( c.modeKnown && !c.binary )
  {
    std::string msg = "### error request declined\n";
    sendAll( c.fd, msg.data(), msg.size() );
  }
  else
    sendStatus( c.fd, code, arg );
  closeConn( it );
}

// parse NUL-separated strings; false if not exactly n well-formed strings
static bool parseStrings( const char *p, size_t len, uint32_t n, std::vector<std::string> &out, size_t &used )
{
  used = 0;
  for ( uint32_t i = 0; i < n; ++i )
  {
    size_t rem = len - used;
    const char *nulPtr = static_cast<const char *>( memchr( p + used, 0, rem ) );
    if ( !nulPtr )
      return false;
    out.emplace_back( p + used );
    used += ( nulPtr - ( p + used ) ) + 1;
  }
  return true;
}

static uint32_t rd32le( const unsigned char *p )
{ return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }

// Returns: -1 error (conn closed), 0 need more data, 1 request complete
static int parseRequest( std::map<int, Conn>::iterator it )
{
  Conn &c = it->second;

  if ( !c.binary )
  {
    std::string::size_type nl = c.buf.find( '\n' );
    if ( nl == std::string::npos )
    {
      if ( c.buf.size() > ZYPPERD_MAX_TEXTLINE )
      { declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_TOOBIG ); return -1; }
      return 0;
    }
    std::string line = c.buf.substr( 0, nl );
    c.argv.clear();
    c.argv.push_back( "zypper" );
    std::string::size_type pos = 0;
    while ( pos < line.size() )
    {
      std::string::size_type start = line.find_first_not_of( " \t\r", pos );
      if ( start == std::string::npos )
        break;
      std::string::size_type end = line.find_first_of( " \t\r", start );
      if ( end == std::string::npos )
        end = line.size();
      c.argv.push_back( line.substr( start, end - start ) );
      pos = end;
    }
    if ( c.argv.size() < 2 )
    { declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_PROTO ); return -1; }
    return 1;
  }

  if ( c.buf.size() < ZYPPERD_HDR_LEN )
    return 0;
  const unsigned char *h = reinterpret_cast<const unsigned char *>( c.buf.data() );
  if ( memcmp( h, ZYPPERD_MAGIC, ZYPPERD_MAGIC_LEN ) != 0 )
  { declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_PROTO ); return -1; }
  uint32_t argc = rd32le( h + 8 ), envc = rd32le( h + 12 ), paylen = rd32le( h + 16 );
  if ( argc < 1 || argc > ZYPPERD_MAX_ARGC || envc > ZYPPERD_MAX_ENVC
    || paylen > ZYPPERD_MAX_PAYLOAD )
  { declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_TOOBIG ); return -1; }
  if ( c.buf.size() < ZYPPERD_HDR_LEN + paylen )
    return 0;

  const char *pay = c.buf.data() + ZYPPERD_HDR_LEN;
  size_t used = 0, used2 = 0;
  c.argv.clear(); c.env.clear();
  if ( !parseStrings( pay, paylen, argc, c.argv, used )
    || !parseStrings( pay + used, paylen - used, envc, c.env, used2 ) )
  { declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_PROTO ); return -1; }

  // env allowlist enforced daemon-side as well - never trust the client
  static const char *allow[] = ZYPPERD_ENV_ALLOWLIST;
  std::vector<std::string> okEnv;
  for ( const std::string &kv : c.env )
  {
    std::string::size_type eq = kv.find( '=' );
    if ( eq == std::string::npos || eq == 0 )
      continue;
    std::string key = kv.substr( 0, eq );
    for ( int a = 0; allow[a]; ++a )
      if ( key == allow[a] )
      { okEnv.push_back( kv ); break; }
  }
  c.env.swap( okEnv );
  return 1;
}

static void drainAndReexec();
static void shutdownDaemon();

static void dispatchRequest( std::map<int, Conn>::iterator it )
{
  Conn &c = it->second;
  Disposition disp = classify( c );

  MIL << "zypperd request uid=" << c.peer.uid << " pid=" << c.peer.pid
      << " mode=" << ( c.binary ? "binary" : "text" )
      << " disp=" << int( disp ) << " argv=" << c.argv << endl;

  if ( disp == Disposition::Fallback )
  { declineConn( it, ZYPPERD_REPLY_FALLBACK ); return; }

  if ( g_childConn.size() >= g_maxWorkers )
  { declineConn( it, ZYPPERD_REPLY_FALLBACK ); return; }

  // freshness gate: never serve from a pool that no longer matches disk
  if ( disp == Disposition::InProcess )
  {
    switch ( checkStale() )
    {
      case Staleness::Fresh:
        break;
      case Staleness::RpmDbChanged:
        MIL << "zypperd: rpmdb changed, reloading target" << endl;
        try
        {
          God->target()->reload();
          sat::Pool::instance().prepare();
          g_warmStamps = collectStamps( Zypper::instance() );
        }
        catch ( const Exception &e )
        {
          ZYPP_CAUGHT( e );
          declineConn( it, ZYPPERD_REPLY_FALLBACK );
          g_wantReexec = true;
          return;
        }
        break;
      case Staleness::ReposChanged:
        MIL << "zypperd: repo metadata changed, restarting" << endl;
        declineConn( it, ZYPPERD_REPLY_FALLBACK );
        g_wantReexec = true;
        return;
    }
  }

  if ( c.binary )
    sendStatus( c.fd, ZYPPERD_REPLY_STARTED );

  pid_t pid = ::fork();
  if ( pid < 0 )
  { declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_PROTO ); return; }
  if ( pid == 0 )
    runWorkerChild( c, disp ); // never returns

  ::setpgid( pid, pid ); // also from the parent side: no race with kill(-pgid)
  c.child = pid;
  c.state = Conn::RUNNING;
  c.reqDeadline = 0;
  c.closeClientFds(); // the child has them now
  c.buf.clear();
  g_childConn[pid] = c.fd;
  // No special handling after ExecReal finishes: whatever it changed
  // (rpmdb, repos.d, solv caches) is caught by the freshness gate the
  // next time an in-process request arrives.
}

static void handleConnReadable( std::map<int, Conn>::iterator it )
{
  Conn &c = it->second;

  if ( c.state == Conn::RUNNING )
  {
    char b;
    ssize_t n = ::recv( c.fd, &b, 1, MSG_DONTWAIT );
    if ( n == 1 )
    {
      if ( c.child > 0 && ( b == SIGINT || b == SIGHUP || b == SIGTERM ) )
        ::kill( -c.child, b );
    }
    else if ( n == 0 || ( n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR ) )
    {
      // client is gone: tell the worker, give it 5s, then kill
      if ( c.child > 0 && c.killDeadline == 0 )
      {
        ::kill( -c.child, SIGHUP );
        c.killDeadline = nowMono() + 5;
      }
    }
    return;
  }

  // REQUEST state: read data; the first chunk decides binary vs text
  char buf[65536];
  struct iovec iov = { buf, sizeof( buf ) };
  union { struct cmsghdr align; char cbuf[CMSG_SPACE( 16 * sizeof( int ) )]; } u;
  struct msghdr mh;
  memset( &mh, 0, sizeof( mh ) );
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  mh.msg_control = u.cbuf;
  mh.msg_controllen = sizeof( u.cbuf );

  ssize_t n = ::recvmsg( c.fd, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC );
  if ( n < 0 )
  {
    if ( errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR )
      return;
    closeConn( it );
    return;
  }

  // collect any passed fds
  std::vector<int> passed;
  for ( struct cmsghdr *cm = CMSG_FIRSTHDR( &mh ); cm; cm = CMSG_NXTHDR( &mh, cm ) )
  {
    if ( cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS )
    {
      int cnt = ( cm->cmsg_len - CMSG_LEN( 0 ) ) / sizeof( int );
      const int *fds = reinterpret_cast<const int *>( CMSG_DATA( cm ) );
      for ( int i = 0; i < cnt; ++i )
        passed.push_back( fds[i] );
    }
  }

  if ( !c.modeKnown )
  {
    c.modeKnown = true;
    c.binary = !passed.empty();
    if ( c.binary )
    {
      if ( passed.size() != 3 || ( mh.msg_flags & MSG_CTRUNC ) )
      {
        for ( int fd : passed ) ::close( fd );
        declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_PROTO );
        return;
      }
      for ( int i = 0; i < 3; ++i )
        c.clientFds[i] = passed[i];
    }
  }
  else if ( !passed.empty() )
  {
    // fds are only valid in the first message
    for ( int fd : passed ) ::close( fd );
    declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_PROTO );
    return;
  }

  if ( n == 0 )
  {
    // EOF before a complete request
    closeConn( it );
    return;
  }

  c.buf.append( buf, size_t(n) );
  if ( c.buf.size() > ZYPPERD_HDR_LEN + ZYPPERD_MAX_PAYLOAD )
  {
    declineConn( it, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_TOOBIG );
    return;
  }

  int r = parseRequest( it );
  if ( r == 1 )
    dispatchRequest( it );
}

///////////////////////////////////////////////////////////////////
// Child reaping
///////////////////////////////////////////////////////////////////

static void reapChildren()
{
  for ( ;; )
  {
    int status = 0;
    pid_t pid = ::waitpid( -1, &status, WNOHANG );
    if ( pid <= 0 )
      break;

    auto ci = g_childConn.find( pid );
    if ( ci == g_childConn.end() )
      continue;
    auto it = g_conns.find( ci->second );
    g_childConn.erase( ci );
    if ( it == g_conns.end() )
      continue;

    int code = WIFEXITED( status ) ? WEXITSTATUS( status )
             : WIFSIGNALED( status ) ? 128 + WTERMSIG( status )
             : ZYPPER_EXIT_ERR_BUG;
    MIL << "zypperd worker " << pid << " finished, exit " << code << endl;

    Conn &c = it->second;
    if ( c.binary )
      sendStatus( c.fd, ZYPPERD_REPLY_RAN, (unsigned char)code );
    else
    {
      std::string trailer = "### exit " + std::to_string( code ) + "\n";
      sendAll( c.fd, trailer.data(), trailer.size() );
    }
    c.child = -1;
    closeConn( it );
  }
}

///////////////////////////////////////////////////////////////////
// Re-exec (repo metadata changed): drain workers, then start over
///////////////////////////////////////////////////////////////////

static void drainAndReexec()
{
  MIL << "zypperd: draining for re-exec" << endl;

  // requests not yet started: fall back
  for ( auto it = g_conns.begin(); it != g_conns.end(); )
  {
    auto cur = it++;
    if ( cur->second.state == Conn::REQUEST )
      declineConn( cur, ZYPPERD_REPLY_FALLBACK );
  }

  // wait for the running workers (generous, then hard)
  time_t deadline = nowMono() + 30;
  while ( !g_childConn.empty() && nowMono() < deadline )
  {
    struct pollfd pfd = { g_selfpipe[0], POLLIN, 0 };
    if ( ::poll( &pfd, 1, 1000 ) > 0 )
    {
      char tmp[64];
      ssize_t n = ::read( g_selfpipe[0], tmp, sizeof( tmp ) );
      for ( ssize_t i = 0; i < n; ++i )
        if ( tmp[i] == 'T' )
          g_terminating = true;
    }
    reapChildren();
    if ( g_terminating )
      shutdownDaemon();
  }
  for ( auto &p : g_childConn )
    ::kill( -p.first, SIGKILL );
  // their clients get EOF and report a lost connection - honest, and rare

  // hand the listening socket to the fresh instance
  int flags = ::fcntl( g_listenFd, F_GETFD );
  ::fcntl( g_listenFd, F_SETFD, flags & ~FD_CLOEXEC );
  ::setenv( "ZYPPERD_LISTEN_FD", std::to_string( g_listenFd ).c_str(), 1 );
  MIL << "zypperd: re-exec" << endl;
  ::execv( "/proc/self/exe", g_savedArgv );
  ERR << "zypperd: re-exec failed: " << strerror( errno ) << endl;
  ::exit( 1 ); // Restart=always brings us back
}

///////////////////////////////////////////////////////////////////
// Shutdown
///////////////////////////////////////////////////////////////////

static void shutdownDaemon()
{
  MIL << "zypperd: shutting down" << endl;
  for ( auto &p : g_childConn )
    ::kill( -p.first, SIGTERM );
  time_t deadline = nowMono() + 10;
  while ( !g_childConn.empty() && nowMono() < deadline )
  {
    struct pollfd pfd = { g_selfpipe[0], POLLIN, 0 };
    if ( ::poll( &pfd, 1, 1000 ) > 0 )
    {
      char tmp[64];
      (void)!read( g_selfpipe[0], tmp, sizeof( tmp ) );
    }
    reapChildren();
  }
  for ( auto &p : g_childConn )
    ::kill( -p.first, SIGKILL );
  if ( g_boundSocketOurselves && !g_socketPath.empty() )
    ::unlink( g_socketPath.c_str() );
  ::exit( 0 );
}

///////////////////////////////////////////////////////////////////
// Socket setup
///////////////////////////////////////////////////////////////////

static int createOrAdoptListenSocket( const std::string &path )
{
  // 1. our own re-exec
  if ( const char *envfd = ::getenv( "ZYPPERD_LISTEN_FD" ) )
  {
    int fd = atoi( envfd );
    ::unsetenv( "ZYPPERD_LISTEN_FD" );
    if ( fd > 2 && ::fcntl( fd, F_GETFD ) >= 0 )
    {
      ::fcntl( fd, F_SETFD, FD_CLOEXEC );
      return fd;
    }
  }

  // 2. systemd socket activation (hand-rolled sd_listen_fds)
  if ( const char *lpid = ::getenv( "LISTEN_PID" ) )
  {
    if ( atoi( lpid ) == getpid() )
    {
      const char *lfds = ::getenv( "LISTEN_FDS" );
      if ( lfds && atoi( lfds ) >= 1 )
      {
        ::fcntl( 3, F_SETFD, FD_CLOEXEC );
        return 3;
      }
    }
  }

  // 3. bind ourselves
  struct sockaddr_un sa;
  if ( path.size() >= sizeof( sa.sun_path ) )
  {
    std::cerr << "zypperd: socket path too long: " << path << std::endl;
    return -1;
  }

  // best effort for the default /run/zypperd directory
  std::string dir = path.substr( 0, path.rfind( '/' ) );
  if ( !dir.empty() )
    ::mkdir( dir.c_str(), 0755 );

  int fd = ::socket( AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0 );
  if ( fd < 0 )
  { perror( "zypperd: socket" ); return -1; }
  memset( &sa, 0, sizeof( sa ) );
  sa.sun_family = AF_UNIX;
  strcpy( sa.sun_path, path.c_str() );
  ::unlink( path.c_str() );
  if ( ::bind( fd, (struct sockaddr *)&sa, sizeof( sa ) ) < 0 )
  { perror( "zypperd: bind" ); ::close( fd ); return -1; }
  ::chmod( path.c_str(), 0666 );
  if ( ::listen( fd, 64 ) < 0 )
  { perror( "zypperd: listen" ); ::close( fd ); return -1; }
  g_boundSocketOurselves = true;
  return fd;
}

///////////////////////////////////////////////////////////////////
// Warmup
///////////////////////////////////////////////////////////////////

static int warmup( const std::string &rootOpt )
{
  Zypper &zypper = Zypper::instance();

  if ( !rootOpt.empty() )
  {
    // testing aid: like --root, without going through option parsing
    Config &cfg = zypper.configNoConst();
    cfg.root_dir = rootOpt;
    cfg.changedRoot = true;
    cfg.rm_options = RepoManagerOptions( rootOpt );
    ::setenv( "ZYPP_LOCKFILE_ROOT", rootOpt.c_str(), 1 );
  }

  // The pool must be loadable without touching the network, and the
  // daemon must never block regular zypper: no global lock, no refresh.
  zypper.configNoConst().no_refresh = true;
  zypp_readonly_hack::IWantIt();

  try
  {
    God = getZYpp();
    zypper.initRepoManager();
    init_target( zypper );
    init_repos( zypper );
    load_resolvables( zypper );
    God->pool(); // establish the ResPool proxy
    sat::Pool::instance().prepare(); // whatprovides index, shared via COW
  }
  catch ( const Exception &e )
  {
    ZYPP_CAUGHT( e );
    std::cerr << "zypperd: cannot load the pool: " << e.asUserString() << std::endl;
    return 1;
  }

  if ( zypper.exitCode() != ZYPPER_EXIT_OK )
  {
    std::cerr << "zypperd: pool load failed, exit code " << zypper.exitCode() << std::endl;
    return 1;
  }

  MIL << "zypperd: pool loaded, " << sat::Pool::instance().solvablesSize()
      << " solvables" << endl;
  return 0;
}

///////////////////////////////////////////////////////////////////
// main
///////////////////////////////////////////////////////////////////

static void usage()
{
  std::cout <<
    "Usage: zypperd [options]\n"
    "Persistent zypper daemon; serves queries from a preloaded pool.\n"
    "\n"
    "  --socket PATH   listen here (default " << ZYPPERD_SOCKET_DEFAULT << ",\n"
    "                  or $" << ZYPPERD_SOCKET_ENV << ")\n"
    "  --root DIR      operate on a different root (testing)\n"
    "  --max-workers N max parallel worker children (default 8)\n"
    "  --help          this text\n";
}

int main( int argc, char **argv )
{
  g_savedArgv = argv;

  std::string rootOpt;
  if ( const char *env = ::getenv( ZYPPERD_SOCKET_ENV ) )
    g_socketPath = env;
  if ( g_socketPath.empty() )
    g_socketPath = ZYPPERD_SOCKET_DEFAULT;

  for ( int i = 1; i < argc; ++i )
  {
    std::string a = argv[i];
    if ( a == "--socket" && i + 1 < argc )
      g_socketPath = argv[++i];
    else if ( a == "--root" && i + 1 < argc )
      rootOpt = argv[++i];
    else if ( a == "--max-workers" && i + 1 < argc )
      g_maxWorkers = std::max( 1, atoi( argv[++i] ) );
    else if ( a == "--help" || a == "-h" )
    { usage(); return 0; }
    else
    { usage(); return 1; }
  }

  // process setup, mirroring src/main.cc
  ::setlocale( LC_ALL, "" );
  bindtextdomain( PACKAGE, LOCALEDIR );
  textdomain( PACKAGE );

  const char *logfile = ::getenv( "ZYPP_LOGFILE" );
  if ( !logfile )
    logfile = ::geteuid() == 0 ? ZYPPERD_LOG : "/dev/null";
  base::LogControl::instance().logfile( logfile );

  MIL << "===== zypperd " VERSION " starting =====" << endl;

  // the graceful-exit strings the copied signal handlers print
  static std::string once = str::Format( "\n%1%\n" ) % _("Trying to exit gracefully...");
  static std::string twice = str::Format( "\n%1%\n" ) % _("Zypper is currently cleaning up, exiting as soon as possible.");
  exit_requested_once_str = once.c_str();
  exit_requested_twice_str = twice.c_str();

  if ( ::pipe2( g_selfpipe, O_CLOEXEC | O_NONBLOCK ) < 0 )
  { perror( "zypperd: pipe2" ); return 1; }

  ::signal( SIGPIPE, SIG_IGN );
  struct sigaction sa;
  memset( &sa, 0, sizeof( sa ) );
  sa.sa_handler = parent_signal_handler;
  sa.sa_flags = SA_RESTART;
  sigaction( SIGCHLD, &sa, nullptr );
  sigaction( SIGTERM, &sa, nullptr );
  sigaction( SIGINT, &sa, nullptr );
  sigaction( SIGHUP, &sa, nullptr );

  try
  {
    static RpmCallbacks rpm_callbacks;
    static SourceCallbacks source_callbacks;
    static MediaCallbacks media_callbacks;
    static KeyRingCallbacks keyring_callbacks;
    static DigestCallbacks digest_callbacks;
    static LocksCallbacks locks_callbacks;
    static JobCallbacks job_callbacks;
  }
  catch ( ... )
  {
    std::cerr << "zypperd: failed to initialize zypper callbacks" << std::endl;
    return ZYPPER_EXIT_ERR_BUG;
  }

  g_listenFd = createOrAdoptListenSocket( g_socketPath );
  if ( g_listenFd < 0 )
    return 1;
  ::fcntl( g_listenFd, F_SETFL, ::fcntl( g_listenFd, F_GETFL ) | O_NONBLOCK );

  if ( int rc = warmup( rootOpt ) )
    return rc;

  g_warmStamps = collectStamps( Zypper::instance() );
  MIL << "zypperd: listening on " << g_socketPath << endl;

  ///////////////////////////////////////////////////////////////////
  // main loop
  ///////////////////////////////////////////////////////////////////
  for ( ;; )
  {
    if ( g_terminating )
      shutdownDaemon();
    if ( g_wantReexec && g_childConn.empty() )
      drainAndReexec();

    std::vector<struct pollfd> pfds;
    pfds.push_back( { g_selfpipe[0], POLLIN, 0 } );
    bool accepting = !g_wantReexec && g_conns.size() < 128;
    if ( accepting )
      pfds.push_back( { g_listenFd, POLLIN, 0 } );
    std::vector<int> connFds;
    time_t now = nowMono();
    int timeout = -1;
    for ( auto &p : g_conns )
    {
      pfds.push_back( { p.first, POLLIN, 0 } );
      connFds.push_back( p.first );
      for ( time_t dl : { p.second.reqDeadline, p.second.killDeadline } )
        if ( dl )
        {
          int ms = dl > now ? int( dl - now ) * 1000 : 0;
          if ( timeout < 0 || ms < timeout )
            timeout = ms;
        }
    }

    int rc = ::poll( pfds.data(), pfds.size(), timeout );
    if ( rc < 0 && errno != EINTR )
    { perror( "zypperd: poll" ); return 1; }

    // self-pipe first: reap before touching connections
    if ( pfds[0].revents & POLLIN )
    {
      char tmp[256];
      ssize_t n;
      bool chld = false;
      while ( ( n = ::read( g_selfpipe[0], tmp, sizeof( tmp ) ) ) > 0 )
        for ( ssize_t i = 0; i < n; ++i )
        {
          if ( tmp[i] == 'T' ) g_terminating = true;
          else if ( tmp[i] == 'H' ) g_wantReexec = true;
          else if ( tmp[i] == 'C' ) chld = true;
        }
      if ( chld )
        reapChildren();
      if ( g_terminating )
        shutdownDaemon();
    }

    size_t idx = 1;
    if ( accepting )
    {
      if ( pfds[idx].revents & POLLIN )
      {
        for ( ;; )
        {
          int cfd = ::accept4( g_listenFd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC );
          if ( cfd < 0 )
            break;
          Conn c;
          c.fd = cfd;
          c.reqDeadline = nowMono() + 5;
          socklen_t ulen = sizeof( c.peer );
          ::getsockopt( cfd, SOL_SOCKET, SO_PEERCRED, &c.peer, &ulen );
          g_conns.emplace( cfd, std::move( c ) );
        }
      }
      ++idx;
    }

    for ( size_t k = 0; k < connFds.size(); ++k )
    {
      auto it = g_conns.find( connFds[k] );
      if ( it == g_conns.end() )
        continue;
      short rev = pfds[idx + k].revents;
      if ( rev & ( POLLIN | POLLHUP | POLLERR ) )
        handleConnReadable( it );
    }

    // deadlines
    now = nowMono();
    for ( auto it = g_conns.begin(); it != g_conns.end(); )
    {
      auto cur = it++;
      Conn &c = cur->second;
      if ( c.state == Conn::REQUEST && c.reqDeadline && now >= c.reqDeadline )
        declineConn( cur, ZYPPERD_REPLY_ERROR, ZYPPERD_ERR_TIMEOUT );
      else if ( c.state == Conn::RUNNING && c.killDeadline && now >= c.killDeadline )
      {
        if ( c.child > 0 )
          ::kill( -c.child, SIGKILL );
        c.killDeadline = 0; // reapChildren will close the conn
      }
    }
  }
}
