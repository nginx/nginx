#ifndef _NGX_SERVER_H_INCLUDED_
#define _NGX_SERVER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_alloc.h>

typedef struct {
    int          log_level;
    ngx_pool_t  *pool;
    int        (*handler)(void *data);
    int          buff_size;
} ngx_server_t;


typedef struct {
    ngx_socket_t  fd;

    ngx_log_t    *log;
    ngx_server_t *server;

    unsigned      shared:1;
#if (HAVE_DEFERRED_ACCEPT)
    unsigned      accept_filter:1;
#endif
} ngx_listen_t;


#endif /* _NGX_SERVER_H_INCLUDED_ */
