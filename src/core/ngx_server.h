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
    void         *server;

    int           family;
    int           type;
    int           protocol;

    void         *addr;
    size_t        addr_len;
    char         *addr_text;

    int           backlog;

    unsigned      non_blocking:1;
    unsigned      shared:1;          /* shared between threads or processes */
#if (HAVE_DEFERRED_ACCEPT)
    unsigned      deferred_accept:1;
#endif
} ngx_listen_t;


#endif /* _NGX_SERVER_H_INCLUDED_ */
