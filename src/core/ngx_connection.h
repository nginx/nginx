
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


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

    void            (*handler)(ngx_connection_t *c); /* handler of accepted
                                                        connection */
    void             *ctx;        /* ngx_http_conf_ctx_t, for example */
    void             *servers;    /* array of ngx_http_in_addr_t, for example */

    ngx_log_t        *log;
    int               backlog;

    size_t            pool_size;
    size_t            post_accept_buffer_size; /* should be here because
                                                  of the AcceptEx() preread */
    time_t            post_accept_timeout;     /* should be here because
                                                  of the deferred accept */

    unsigned          new:1;
    unsigned          remain:1;
    unsigned          ignore:1;

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

    unsigned          addr_ntop:1;
} ngx_listening_t;


typedef enum {
     NGX_ERROR_CRIT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NOPUSH_DISABLED = -1,
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET
} ngx_connection_tcp_nopush_e;


struct ngx_connection_s {
    void               *data;
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    ngx_recv_pt         recv;
    ngx_send_chain_pt   send_chain;

    ngx_listening_t    *listening;

    off_t               sent;

    void               *ctx;
    void               *servers;


    ngx_log_t          *log;

    ngx_pool_t         *pool;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text;

#if (NGX_OPENSSL)
    ngx_ssl_t          *ssl;
#endif

#if (HAVE_IOCP)
    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;
#endif

    ngx_buf_t          *buffer;

    ngx_uint_t          number;

    unsigned            log_error:2;  /* ngx_connection_log_error_e */

    unsigned            buffered:1;
    unsigned            single_connection:1;
    unsigned            unexpected_eof:1;
    unsigned            timedout:1;
    signed              tcp_nopush:2;
#if (HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
};


#ifndef ngx_ssl_set_nosendshut
#define ngx_ssl_set_nosendshut(ssl)
#endif


ngx_listening_t *ngx_listening_inet_stream_socket(ngx_conf_t *cf,
                                                 in_addr_t addr,
                                                 in_port_t port);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);


extern ngx_os_io_t  ngx_io;


#endif /* _NGX_CONNECTION_H_INCLUDED_ */
