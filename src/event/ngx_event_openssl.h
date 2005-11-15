
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_OPENSSL_H_INCLUDED_
#define _NGX_EVENT_OPENSSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER >= 0x00907000
#include <openssl/engine.h>
#define NGX_SSL_ENGINE   1
#endif

#define NGX_SSL_NAME     "OpenSSL"


typedef struct {
    SSL_CTX                    *ctx;
    RSA                        *rsa512_key;
    ngx_log_t                  *log;
} ngx_ssl_t;


typedef struct {
    SSL                        *connection;
    ngx_int_t                   last;
    ngx_buf_t                  *buf;

    ngx_connection_handler_pt   handler;

    ngx_event_handler_pt        saved_read_handler;
    ngx_event_handler_pt        saved_write_handler;

    unsigned                    handshaked:1;
    unsigned                    buffer:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
} ngx_ssl_connection_t;


#define ngx_ssl_session_t       SSL_SESSION


#define NGX_SSL_SSLv2    2
#define NGX_SSL_SSLv3    4
#define NGX_SSL_TLSv1    8


#define NGX_SSL_BUFFER   1
#define NGX_SSL_CLIENT   2

#define NGX_SSL_BUFSIZE  16384


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key);
ngx_int_t ngx_ssl_generate_rsa512_key(ngx_ssl_t *ssl);
ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);

ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
#define ngx_ssl_get_session(c)   SSL_get1_session(c->ssl->connection)
#define ngx_ssl_free_session     SSL_SESSION_free

ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


#endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
