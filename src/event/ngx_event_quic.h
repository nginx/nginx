
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_event_openssl.h>

struct ngx_quic_stream_s {
    uint64_t            id;
    ngx_uint_t          unidirectional:1;
    ngx_connection_t   *parent;
    void               *data;
};

/* TODO: get rid somehow of ssl argument? */
ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_buf_t *b);
ngx_int_t ngx_quic_output(ngx_connection_t *c);

void ngx_quic_init_ssl_methods(SSL_CTX* ctx);

void ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_msec_t timeout,
    ngx_connection_handler_pt handler);
ngx_connection_t *ngx_quic_create_uni_stream(ngx_connection_t *c);

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
