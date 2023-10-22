
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>


#define NGX_WRITE_SHUTDOWN SHUT_WR
#define NGX_READ_SHUTDOWN  SHUT_RD
#define NGX_RDWR_SHUTDOWN  SHUT_RDWR

typedef int  ngx_socket_t;

#define ngx_socket          socket
#define ngx_socket_n        "socket()"


#if (NGX_HAVE_FIONBIO)

int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ioctl(FIONBIO)"
#define ngx_blocking_n      "ioctl(!FIONBIO)"

#else

#define ngx_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define ngx_nonblocking_n   "fcntl(O_NONBLOCK)"

#define ngx_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define ngx_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

#if (NGX_HAVE_FIONREAD)

#define ngx_socket_nread(s, n)  ioctl(s, FIONREAD, n)
#define ngx_socket_nread_n      "ioctl(FIONREAD)"

#endif

int ngx_tcp_nopush(ngx_socket_t s);
int ngx_tcp_push(ngx_socket_t s);

#if (NGX_LINUX)

#define ngx_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define ngx_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define ngx_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define ngx_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif


#define ngx_shutdown_socket    shutdown
#define ngx_shutdown_socket_n  "shutdown()"

#define ngx_close_socket    close
#define ngx_close_socket_n  "close() socket"


#endif /* _NGX_SOCKET_H_INCLUDED_ */
