
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_peers_t        *peers;
    ngx_uint_t          cur_peer;
    ngx_uint_t          tries;

    ngx_connection_t   *connection;
#if (NGX_THREADS)
    ngx_atomic_t       *lock;
#endif

    int                 rcvbuf;

    ngx_log_t          *log;

    unsigned            cached:1;
    unsigned            log_error:2;  /* ngx_connection_log_error_e */
} ngx_peer_connection_t;


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
void ngx_event_connect_peer_failed(ngx_peer_connection_t *pc, ngx_uint_t down);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
