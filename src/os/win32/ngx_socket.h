
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_WRITE_SHUTDOWN SD_SEND
#define NGX_READ_SHUTDOWN  SD_RECEIVE
#define NGX_RDWR_SHUTDOWN  SD_BOTH


typedef SOCKET  ngx_socket_t;
typedef int     socklen_t;


#define ngx_socket(af, type, proto)                                          \
    WSASocketW(af, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED)

#define ngx_socket_n        "WSASocketW()"

int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ioctlsocket(FIONBIO)"
#define ngx_blocking_n      "ioctlsocket(!FIONBIO)"

int ngx_socket_nread(ngx_socket_t s, int *n);
#define ngx_socket_nread_n  "ioctlsocket(FIONREAD)"

#define ngx_shutdown_socket    shutdown
#define ngx_shutdown_socket_n  "shutdown()"

#define ngx_close_socket    closesocket
#define ngx_close_socket_n  "closesocket()"


#if (NGX_HAVE_POLL && !defined POLLIN)

/*
 * WSAPoll() is only available if _WIN32_WINNT >= 0x0600.
 * If it is not available during compilation, we try to
 * load it dynamically at runtime.
 */

#define NGX_LOAD_WSAPOLL 1

#define POLLRDNORM  0x0100
#define POLLRDBAND  0x0200
#define POLLIN      (POLLRDNORM | POLLRDBAND)
#define POLLPRI     0x0400

#define POLLWRNORM  0x0010
#define POLLOUT     (POLLWRNORM)
#define POLLWRBAND  0x0020

#define POLLERR     0x0001
#define POLLHUP     0x0002
#define POLLNVAL    0x0004

typedef struct pollfd {

    SOCKET  fd;
    SHORT   events;
    SHORT   revents;

} WSAPOLLFD, *PWSAPOLLFD, FAR *LPWSAPOLLFD;

typedef int (WSAAPI *ngx_wsapoll_pt)(
    LPWSAPOLLFD fdArray,
    ULONG fds,
    INT timeout
    );

extern ngx_wsapoll_pt             WSAPoll;
extern ngx_uint_t                 ngx_have_wsapoll;

#endif


int ngx_tcp_push(ngx_socket_t s);
#define ngx_tcp_push_n            "tcp_push()"


#endif /* _NGX_SOCKET_H_INCLUDED_ */
