#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>

#ifdef __FreeBSD__
#include <sys/ioctl.h>
#endif


#define NGX_WRITE_SHUTDOWN SHUT_WR

typedef int  ngx_socket_t;

#define ngx_socket(af, type, proto, flags)   socket(af, type, proto)
#define ngx_socket_n        "socket()"


#ifdef __FreeBSD__

int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ioctl(FIONBIO)"
#define ngx_blocking_n      "ioctl(!FIONBIO)"

#else

#define ngx_nonblocking(s)  fcntl(s, F_SETFL, O_NONBLOCK)
#define ngx_nonblocking_n   "fcntl(O_NONBLOCK)"

#endif


#define ngx_shutdown_socket    shutdown
#define ngx_shutdown_socket_n  "shutdown()"

#define ngx_close_socket    close
#define ngx_close_socket_n  "close()"


#endif /* _NGX_SOCKET_H_INCLUDED_ */
