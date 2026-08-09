/*---------------------------------------------------------------------------*\
                          ____  _ _ __ _ __  ___ _ _
                         |_ / || | '_ \ '_ \/ -_) '_|
                         /__|\_, | .__/ .__/\___|_|
                             |__/|_|  |_|
\*---------------------------------------------------------------------------*/
#ifndef ZYPPERD_PROTOCOL_H
#define ZYPPERD_PROTOCOL_H

/*
 * Wire protocol shared by zypperd (C++) and zypperc (plain C).
 * One request per connection on a SOCK_STREAM UNIX socket.
 *
 * Binary mode (zypperc):
 *   The client sends one sendmsg() whose ancillary data carries its
 *   fds 0,1,2 via SCM_RIGHTS and whose payload starts with:
 *
 *     offset 0  : char[8]  magic  "ZYPRDv1\n"
 *     offset 8  : uint32le argc   (1..ZYPPERD_MAX_ARGC)
 *     offset 12 : uint32le envc   (0..ZYPPERD_MAX_ENVC)
 *     offset 16 : uint32le paylen (bytes after this 20-byte header)
 *     offset 20 : argc NUL-terminated argv strings,
 *                 then envc NUL-terminated "KEY=VALUE" strings
 *
 *   Payload exceeding the first datagram is sent with plain send().
 *   The daemon replies with 2-byte status frames:
 *     'S' 0           worker started (always precedes 'R'); after this
 *                     the client may no longer fall back
 *     'R' <exitcode>  command finished; exit with <exitcode>
 *     'F' 0           declined; client must exec /usr/bin/zypper itself
 *     'E' <reason>    protocol error before execution; ditto
 *   'F' and 'E' are only ever sent before 'S', so a connection that dies
 *   without any frame provably ran nothing and the client may fall back.
 *   After sending the request the client may send single bytes, each a
 *   signal number from the set {SIGHUP=1, SIGINT=2, SIGTERM=15} to be
 *   forwarded to the worker's process group.
 *
 * Text mode (nc -U):
 *   Anything arriving without SCM_RIGHTS. One line "<cmd> [args...]\n",
 *   whitespace-split, always --non-interactive, read-only commands only.
 *   stdout+stderr come back interleaved on the socket, then a trailer
 *   line "### exit <code>" and close.
 */

#define ZYPPERD_MAGIC        "ZYPRDv1\n"
#define ZYPPERD_MAGIC_LEN    8
#define ZYPPERD_HDR_LEN      20

#define ZYPPERD_MAX_ARGC     1024
#define ZYPPERD_MAX_ENVC     64
#define ZYPPERD_MAX_PAYLOAD  (128*1024)
#define ZYPPERD_MAX_TEXTLINE 8192

#define ZYPPERD_REPLY_STARTED  'S'
#define ZYPPERD_REPLY_RAN      'R'
#define ZYPPERD_REPLY_FALLBACK 'F'
#define ZYPPERD_REPLY_ERROR    'E'

/* 'E' reason bytes */
#define ZYPPERD_ERR_PROTO    1  /* malformed frame */
#define ZYPPERD_ERR_TOOBIG   2  /* caps exceeded */
#define ZYPPERD_ERR_TIMEOUT  3  /* request not complete in time */

#define ZYPPERD_SOCKET_DEFAULT "/run/zypperd/zypperd.sock"
#define ZYPPERD_SOCKET_ENV     "ZYPPERD_SOCKET"

/* env vars a client may forward; anything else (esp. ZYPP_*) is dropped */
#define ZYPPERD_ENV_ALLOWLIST \
  { "LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE", "LC_TIME", "LC_NUMERIC", \
    "TERM", "COLUMNS", "LINES", (const char *)0 }

#endif /* ZYPPERD_PROTOCOL_H */
