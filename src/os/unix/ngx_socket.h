#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>


typedef int  ngx_socket_t;

#define ngx_init_sockets

#define ngx_nonblocking(s)  fcntl(s, F_SETFL, O_NONBLOCK)
#define ngx_nonblocking_n   "fcntl (O_NONBLOCK)"

#define ngx_close_socket    close
#define ngx_close_socket_n  "close"


#endif /* _NGX_SOCKET_H_INCLUDED_ */
