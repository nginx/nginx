
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_CONNECT_ERROR   -10


typedef struct {
    in_addr_t          addr;
    ngx_str_t          host;
    in_port_t          port;
    ngx_str_t          addr_port_text;

    ngx_int_t          fails;
    time_t             accessed;
} ngx_peer_t;


typedef struct {
    ngx_int_t           current;
    ngx_int_t           number;
    ngx_int_t           max_fails;
    ngx_int_t           fail_timeout;
    ngx_int_t           last_cached;

 /* ngx_mutex_t        *mutex; */
    ngx_connection_t  **cached;

    ngx_peer_t          peers[1];
} ngx_peers_t;


typedef struct {
    ngx_peers_t       *peers;
    ngx_int_t          cur_peer;
    ngx_int_t          tries;

    ngx_connection_t  *connection;
#if (NGX_THREADS)
    ngx_atomic_t      *lock;
#endif

    int                rcvbuf;

    ngx_log_t         *log;

    unsigned           cached:1;
    unsigned           log_error:2;  /* ngx_connection_log_error_e */
} ngx_peer_connection_t;


int ngx_event_connect_peer(ngx_peer_connection_t *pc);
void ngx_event_connect_peer_failed(ngx_peer_connection_t *pc);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
