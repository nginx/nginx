
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_event_openssl.h>

/* TODO: get rid somehow of ssl argument? */
ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_buf_t *b);
ngx_int_t ngx_quic_output(ngx_connection_t *c);

void ngx_quic_init_ssl_methods(SSL_CTX* ctx);


#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
