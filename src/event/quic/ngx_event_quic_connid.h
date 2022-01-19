
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_CONNID_H_INCLUDED_
#define _NGX_EVENT_QUIC_CONNID_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_retire_cid_frame_t *f);
ngx_int_t ngx_quic_handle_new_connection_id_frame(ngx_connection_t *c,
    ngx_quic_new_conn_id_frame_t *f);

ngx_int_t ngx_quic_create_sockets(ngx_connection_t *c);
ngx_int_t ngx_quic_create_server_id(ngx_connection_t *c, u_char *id);

ngx_quic_client_id_t *ngx_quic_create_client_id(ngx_connection_t *c,
    ngx_str_t *id, uint64_t seqnum, u_char *token);
ngx_quic_client_id_t *ngx_quic_next_client_id(ngx_connection_t *c);
ngx_int_t ngx_quic_free_client_id(ngx_connection_t *c,
    ngx_quic_client_id_t *cid);

#endif /* _NGX_EVENT_QUIC_CONNID_H_INCLUDED_ */
