
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_OUTPUT_H_INCLUDED_
#define _NGX_EVENT_QUIC_OUTPUT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_output(ngx_connection_t *c);

ngx_int_t ngx_quic_negotiate_version(ngx_connection_t *c,
    ngx_quic_header_t *inpkt);

ngx_int_t ngx_quic_send_stateless_reset(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
ngx_int_t ngx_quic_send_cc(ngx_connection_t *c);
ngx_int_t ngx_quic_send_early_cc(ngx_connection_t *c,
    ngx_quic_header_t *inpkt, ngx_uint_t err, const char *reason);

ngx_int_t ngx_quic_send_retry(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
ngx_int_t ngx_quic_send_new_token(ngx_connection_t *c, ngx_quic_path_t *path);

ngx_int_t ngx_quic_send_ack(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
ngx_int_t ngx_quic_send_ack_range(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t smallest, uint64_t largest);

ngx_int_t ngx_quic_frame_sendto(ngx_connection_t *c, ngx_quic_frame_t *frame,
    size_t min, ngx_quic_path_t *path);
size_t ngx_quic_path_limit(ngx_connection_t *c, ngx_quic_path_t *path,
    size_t size);

#endif /* _NGX_EVENT_QUIC_OUTPUT_H_INCLUDED_ */
