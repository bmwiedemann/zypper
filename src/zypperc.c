/*---------------------------------------------------------------------------*\
                          ____  _ _ __ _ __  ___ _ _
                         |_ / || | '_ \ '_ \/ -_) '_|
                         /__|\_, | .__/ .__/\___|_|
                             |__/|_|  |_|
\*---------------------------------------------------------------------------*/
/*
 * zypperc - thin client for zypperd
 *
 * Sends its argv, a small env allowlist and its fds 0,1,2 to zypperd over
 * a UNIX socket, then waits for the exit code. If the daemon is absent,
 * declines the request, or anything at all goes wrong before the command
 * was started daemon-side, it transparently execs /usr/bin/zypper instead.
 * Plain C, no dependencies beyond libc: the whole point is that the
 * fast path costs ~1 ms before zypperd starts doing real work.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "zypperd-protocol.h"

#define REAL_ZYPPER "/usr/bin/zypper"

static char **g_argv;
static volatile int g_sock = -1;

static void fallback_exec( void )
{
  if ( getenv( "ZYPPERC_DEBUG" ) )
    fprintf( stderr, "zypperc: zypperd unavailable, running %s\n", REAL_ZYPPER );
  execv( REAL_ZYPPER, g_argv );
  perror( "zypperc: exec " REAL_ZYPPER );
  _exit( 127 );
}

/* connect with a deadline so a wedged daemon can not hang the client */
static int connect_daemon( const char *path, int timeout_ms )
{
  struct sockaddr_un sa;
  int fd;

  if ( strlen( path ) >= sizeof( sa.sun_path ) )
    return -1;
  fd = socket( AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0 );
  if ( fd < 0 )
    return -1;
  memset( &sa, 0, sizeof( sa ) );
  sa.sun_family = AF_UNIX;
  strcpy( sa.sun_path, path );
  if ( connect( fd, (struct sockaddr *)&sa, sizeof( sa ) ) < 0 )
  {
    struct pollfd pfd = { fd, POLLOUT, 0 };
    int err = 0;
    socklen_t len = sizeof( err );
    if ( errno != EINPROGRESS
      || poll( &pfd, 1, timeout_ms ) != 1
      || getsockopt( fd, SOL_SOCKET, SO_ERROR, &err, &len ) < 0
      || err != 0 )
    {
      close( fd );
      return -1;
    }
  }
  /* back to blocking for the rest of the conversation */
  fcntl( fd, F_SETFL, fcntl( fd, F_GETFL ) & ~O_NONBLOCK );
  return fd;
}

static int send_all( int fd, const void *buf, size_t len )
{
  const char *p = buf;
  while ( len )
  {
    ssize_t n = send( fd, p, len, MSG_NOSIGNAL );
    if ( n < 0 )
    {
      if ( errno == EINTR )
        continue;
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

/* forward a few signals as single bytes; write() is async-signal-safe */
static void sig_forward( int signo )
{
  char b = (char)signo;
  if ( g_sock >= 0 )
    (void)!write( g_sock, &b, 1 );
}

int main( int argc, char **argv )
{
  static const char *env_allow[] = ZYPPERD_ENV_ALLOWLIST;
  const char *path;
  char *payload;
  unsigned char hdr[ZYPPERD_HDR_LEN];
  uint32_t envc = 0, paylen = 0;
  size_t cap;
  int fd, i;

  g_argv = argv;

  path = getenv( ZYPPERD_SOCKET_ENV );
  if ( !path || !*path )
    path = ZYPPERD_SOCKET_DEFAULT;

  if ( argc < 1 || argc > ZYPPERD_MAX_ARGC )
    fallback_exec();

  /* build payload: argv strings, then allowlisted env strings */
  cap = 0;
  for ( i = 0; i < argc; ++i )
    cap += strlen( argv[i] ) + 1;
  for ( i = 0; env_allow[i]; ++i )
  {
    const char *v = getenv( env_allow[i] );
    if ( v )
      cap += strlen( env_allow[i] ) + 1 + strlen( v ) + 1;
  }
  if ( cap > ZYPPERD_MAX_PAYLOAD )
    fallback_exec();
  payload = malloc( cap ? cap : 1 );
  if ( !payload )
    fallback_exec();
  for ( i = 0; i < argc; ++i )
  {
    size_t l = strlen( argv[i] ) + 1;
    memcpy( payload + paylen, argv[i], l );
    paylen += (uint32_t)l;
  }
  for ( i = 0; env_allow[i]; ++i )
  {
    const char *v = getenv( env_allow[i] );
    if ( v )
    {
      int n = snprintf( payload + paylen, cap - paylen, "%s=%s", env_allow[i], v );
      paylen += (uint32_t)n + 1;
      ++envc;
    }
  }

  memcpy( hdr, ZYPPERD_MAGIC, ZYPPERD_MAGIC_LEN );
  hdr[8]  = (unsigned char)( argc & 0xff );
  hdr[9]  = (unsigned char)( ( argc >> 8 ) & 0xff );
  hdr[10] = (unsigned char)( ( argc >> 16 ) & 0xff );
  hdr[11] = (unsigned char)( ( (unsigned)argc >> 24 ) & 0xff );
  hdr[12] = (unsigned char)( envc & 0xff );
  hdr[13] = (unsigned char)( ( envc >> 8 ) & 0xff );
  hdr[14] = (unsigned char)( ( envc >> 16 ) & 0xff );
  hdr[15] = (unsigned char)( ( envc >> 24 ) & 0xff );
  hdr[16] = (unsigned char)( paylen & 0xff );
  hdr[17] = (unsigned char)( ( paylen >> 8 ) & 0xff );
  hdr[18] = (unsigned char)( ( paylen >> 16 ) & 0xff );
  hdr[19] = (unsigned char)( ( paylen >> 24 ) & 0xff );

  fd = connect_daemon( path, 1000 );
  if ( fd < 0 )
  {
    free( payload );
    fallback_exec();
  }

  /* fds 0,1,2 travel via SCM_RIGHTS; substitute /dev/null for closed ones
   * so the daemon always receives exactly three valid descriptors */
  {
    struct msghdr mh;
    struct iovec iov[2];
    union { struct cmsghdr align; char buf[CMSG_SPACE( 3 * sizeof( int ) )]; } u;
    struct cmsghdr *cm;
    int fds[3], nul = -1;
    ssize_t n;

    for ( i = 0; i < 3; ++i )
    {
      if ( fcntl( i, F_GETFL ) >= 0 )
        fds[i] = i;
      else
      {
        if ( nul < 0 )
          nul = open( "/dev/null", i == 0 ? O_RDONLY : O_WRONLY );
        if ( nul < 0 )
        {
          free( payload );
          fallback_exec();
        }
        fds[i] = nul;
      }
    }

    memset( &mh, 0, sizeof( mh ) );
    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof( hdr );
    iov[1].iov_base = payload;
    iov[1].iov_len = paylen;
    mh.msg_iov = iov;
    mh.msg_iovlen = paylen ? 2 : 1;
    mh.msg_control = u.buf;
    mh.msg_controllen = CMSG_SPACE( 3 * sizeof( int ) );
    cm = CMSG_FIRSTHDR( &mh );
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN( 3 * sizeof( int ) );
    memcpy( CMSG_DATA( cm ), fds, 3 * sizeof( int ) );

    do
      n = sendmsg( fd, &mh, MSG_NOSIGNAL );
    while ( n < 0 && errno == EINTR );
    if ( n < 0 )
    {
      free( payload );
      fallback_exec();
    }
    /* anything the kernel did not take in one gulp follows as plain bytes */
    if ( (size_t)n < sizeof( hdr ) + paylen )
    {
      size_t sent = (size_t)n;
      if ( sent < sizeof( hdr ) )
      {
        if ( send_all( fd, hdr + sent, sizeof( hdr ) - sent ) < 0 )
        {
          free( payload );
          fallback_exec();
        }
        sent = sizeof( hdr );
      }
      if ( send_all( fd, payload + ( sent - sizeof( hdr ) ),
                     paylen - ( sent - sizeof( hdr ) ) ) < 0 )
      {
        free( payload );
        fallback_exec();
      }
    }
  }
  free( payload );

  /* request is fully out; from here on Ctrl-C etc. must reach the worker,
   * not kill us, so forward the common job-control signals as bytes */
  g_sock = fd;
  signal( SIGPIPE, SIG_IGN );
  {
    struct sigaction sa;
    memset( &sa, 0, sizeof( sa ) );
    sa.sa_handler = sig_forward;
    sa.sa_flags = 0; /* no SA_RESTART: interrupt the read below on purpose */
    sigaction( SIGINT, &sa, NULL );
    sigaction( SIGTERM, &sa, NULL );
    sigaction( SIGHUP, &sa, NULL );
  }

  /* read 2-byte frames: expect 'F'/'E' (→ fallback), or 'S' then 'R' */
  {
    int started = 0; /* daemon sends 'S' before forking, 'F'/'E' otherwise */
    for ( ;; )
    {
      unsigned char reply[2];
      size_t got = 0;
      int broken = 0;
      while ( got < 2 && !broken )
      {
        ssize_t n = read( fd, reply + got, 2 - got );
        if ( n < 0 )
        {
          if ( errno == EINTR )
            continue;
          broken = 1;
        }
        else if ( n == 0 )
          broken = 1;
        else
          got += (size_t)n;
      }
      if ( got == 1 )
        started = 1; /* half a frame: could be a torn 'S'/'R', assume ran */
      if ( got == 2 )
      {
        if ( reply[0] == ZYPPERD_REPLY_STARTED )
        {
          started = 1;
          continue; /* command is running; wait for 'R' */
        }
        if ( reply[0] == ZYPPERD_REPLY_RAN )
          _exit( reply[1] );
        if ( !started && ( reply[0] == ZYPPERD_REPLY_FALLBACK
                        || reply[0] == ZYPPERD_REPLY_ERROR ) )
        {
          close( fd );
          g_sock = -1;
          fallback_exec();
        }
        /* unknown or out-of-order frame: state unknown, do not re-run */
        started = 1;
      }

      /* Connection lost or garbled. Before 'S' the daemon provably ran
       * nothing, so falling back is safe; after 'S' the command may have
       * (partially) executed and re-running it could be harmful. */
      if ( !started )
      {
        close( fd );
        g_sock = -1;
        fallback_exec();
      }
      fprintf( stderr, "zypperc: lost connection to zypperd\n" );
      _exit( 1 );
    }
  }
}
