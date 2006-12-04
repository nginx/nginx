
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE   1
#define NGX_PEER_NEXT        2
#define NGX_PEER_FAILED      4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);
#if (NGX_SSL)
typedef void (*ngx_event_save_peer_pt)(ngx_peer_connection_t *pc, void *data);
#endif
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);


struct ngx_peer_connection_s {
    ngx_connection_t        *connection;

    struct sockaddr         *sockaddr;
    socklen_t                socklen;
    ngx_str_t               *name;

    ngx_uint_t               tries;

    ngx_event_get_peer_pt    get;
    ngx_event_free_peer_pt   free;
    void                    *data;

#if (NGX_SSL)
    ngx_ssl_session_t       *ssl_session;
    ngx_event_save_peer_pt   save_session;
#endif

#if (NGX_THREADS)
    ngx_atomic_t            *lock;
#endif

    int                      rcvbuf;

    ngx_log_t               *log;

    unsigned                 cached:1;
    unsigned                 log_error:2;  /* ngx_connection_log_error_e */
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);



#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
