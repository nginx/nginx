
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_CONNID_H_INCLUDED_
#define _NGX_EVENT_QUIC_CONNID_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_setup_connection_ids(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_header_t *pkt);
void ngx_quic_clear_temp_server_ids(ngx_connection_t *c);
ngx_int_t ngx_quic_issue_server_ids(ngx_connection_t *c);

ngx_int_t ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_retire_cid_frame_t *f);
ngx_int_t ngx_quic_handle_new_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_new_conn_id_frame_t *f);

#endif /* _NGX_EVENT_QUIC_CONNID_H_INCLUDED_ */
