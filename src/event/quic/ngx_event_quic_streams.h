
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_STREAMS_H_INCLUDED_
#define _NGX_EVENT_QUIC_STREAMS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_handle_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
void ngx_quic_handle_stream_ack(ngx_connection_t *c,
    ngx_quic_frame_t *f);
ngx_int_t ngx_quic_handle_max_data_frame(ngx_connection_t *c,
    ngx_quic_max_data_frame_t *f);
ngx_int_t ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f);
ngx_int_t ngx_quic_handle_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_data_blocked_frame_t *f);
ngx_int_t ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f);
ngx_int_t ngx_quic_handle_max_stream_data_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_stream_data_frame_t *f);
ngx_int_t ngx_quic_handle_reset_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_reset_stream_frame_t *f);
ngx_int_t ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f);
ngx_int_t ngx_quic_handle_max_streams_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_streams_frame_t *f);

ngx_int_t ngx_quic_init_streams(ngx_connection_t *c);
void ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
ngx_quic_stream_t *ngx_quic_find_stream(ngx_rbtree_t *rbtree,
    uint64_t id);
ngx_int_t ngx_quic_close_streams(ngx_connection_t *c,
    ngx_quic_connection_t *qc);

#endif /* _NGX_EVENT_QUIC_STREAMS_H_INCLUDED_ */
