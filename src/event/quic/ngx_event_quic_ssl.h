
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_SSL_H_INCLUDED_
#define _NGX_EVENT_QUIC_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

ngx_int_t ngx_quic_init_connection(ngx_connection_t *c, ngx_uint_t flags);
ngx_int_t ngx_quic_do_handshake(ngx_connection_t *c);

ngx_int_t ngx_quic_handle_crypto_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
ngx_int_t ngx_quic_handle_handshake_done_frame(ngx_connection_t *c);

#endif /* _NGX_EVENT_QUIC_SSL_H_INCLUDED_ */
