#ifndef _NGX_LISTEN_H_INCLUDED_
#define _NGX_LISTEN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_log.h>
#include <ngx_types.h>
#include <ngx_socket.h>
#include <ngx_connection.h>

typedef struct {
    ngx_socket_t  fd;

    void         *addr;
    size_t        addr_len;
    char         *addr_text;

    int           family;
    int           type;
    int           protocol;

    ngx_log_t    *log;
    void         *server;
    int         (*handler)(ngx_connection_t *c);

    int           backlog;

    unsigned      done:1;
    unsigned      close:1;
    unsigned      nonblocking:1;
#if 0
    unsigned      overlapped:1;
#endif
    unsigned      shared:1;          /* shared between threads or processes */
#if (HAVE_DEFERRED_ACCEPT)
    unsigned      deferred_accept:1;
#endif
} ngx_listen_t;


#endif /* _NGX_LISTEN_H_INCLUDED_ */
