
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_OPENSSL_H_INCLUDED_
#define _NGX_EVENT_OPENSSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


typedef struct {
    SSL                   *ssl;
    ngx_int_t              last;
    ngx_buf_t             *buf;
    ngx_event_handler_pt   saved_read_handler;
    ngx_event_handler_pt   saved_write_handler;

    unsigned               buffer:1;
    unsigned               no_rcv_shut:1;
    unsigned               no_send_shut:1;
    unsigned               shutdown_set:1;

#if (NGX_DEBUG)
    unsigned               handshaked:1;
#endif
} ngx_ssl_t;


typedef SSL_CTX  ngx_ssl_ctx_t;


#define NGX_SSL_BUFFER       1


#define NGX_SSL_BUFSIZE      16384


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create_session(ngx_ssl_ctx_t *ctx, ngx_connection_t *c,
                                 ngx_uint_t flags);

#define ngx_ssl_handshake(c)     NGX_OK

ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


#endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
