#ifndef _NGX_LISTEN_H_INCLUDED_
#define _NGX_LISTEN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_log.h>
#include <ngx_types.h>
#include <ngx_socket.h>
#include <ngx_connection.h>

typedef struct {
    ngx_socket_t      fd;

    struct sockaddr  *sockaddr;
    socklen_t         socklen;    /* size of sockaddr */
    int               addr;       /* offset to address in sockaddr */
    int               addr_text_max_len;
    ngx_str_t         addr_text;

    int               family;
    int               type;
    int               protocol;
    int               flags;      /* Winsock2 flags */

    int             (*handler)(ngx_connection_t *c); /* handler of accepted
                                                        connection */
    void             *ctx;        /* ngx_http_conf_ctx_t, for example */
    void             *servers;    /* array of ngx_http_in_addr_t, for example */

    ngx_log_t        *log;
    int               pool_size;

    int               backlog;
    time_t            post_accept_timeout;  /* should be here because
                                               of the deferred accept */

    unsigned          bound:1;       /* already bound */
    unsigned          inherited:1;   /* inherited from previous process */
    unsigned          nonblocking_accept:1;
    unsigned          nonblocking:1;
#if 0
    unsigned          overlapped:1;  /* Winsock2 overlapped */
#endif
    unsigned          shared:1;    /* shared between threads or processes */
#if (HAVE_DEFERRED_ACCEPT)
    unsigned          deferred_accept:1;
#endif
} ngx_listen_t;


extern ngx_array_t ngx_listening_sockets;


#endif /* _NGX_LISTEN_H_INCLUDED_ */
