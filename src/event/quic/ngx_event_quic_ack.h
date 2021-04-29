
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_ACK_H_INCLUDED_
#define _NGX_EVENT_QUIC_ACK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_handle_ack_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *f);

void ngx_quic_congestion_ack(ngx_connection_t *c,
    ngx_quic_frame_t *frame);
void ngx_quic_resend_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx);
void ngx_quic_set_lost_timer(ngx_connection_t *c);
void ngx_quic_pto_handler(ngx_event_t *ev);
ngx_msec_t ngx_quic_pto(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx);

ngx_int_t ngx_quic_ack_packet(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
ngx_int_t ngx_quic_generate_ack(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);

#endif /* _NGX_EVENT_QUIC_ACK_H_INCLUDED_ */
