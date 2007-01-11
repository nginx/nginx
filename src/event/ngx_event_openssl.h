
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
#include <openssl/conf.h>
#include <openssl/engine.h>
#define NGX_SSL_ENGINE   1
#endif

#define NGX_SSL_NAME     "OpenSSL"


#define ngx_ssl_session_t       SSL_SESSION
#define ngx_ssl_conn_t          SSL


typedef struct {
    SSL_CTX                    *ctx;
    ngx_log_t                  *log;
} ngx_ssl_t;


typedef struct {
    ngx_ssl_conn_t             *connection;

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


#define NGX_SSL_DFLT_BUILTIN_SCACHE  -2
#define NGX_SSL_NO_BUILTIN_SCACHE    -3


#define NGX_SSL_MAX_SESSION_SIZE (4096)

typedef struct ngx_ssl_sess_id_s  ngx_ssl_sess_id_t;

struct ngx_ssl_sess_id_s {
    ngx_rbtree_node_t           node;
    u_char                     *id;
    size_t                      len;
    u_char                     *session;
    ngx_ssl_sess_id_t          *prev;
    ngx_ssl_sess_id_t          *next;
    time_t                      expire;
#if (NGX_PTR_SIZE == 8)
    void                       *stub;
    u_char                      sess_id[32];
#endif
};


typedef struct {
    ngx_rbtree_t               *session_rbtree;
    ngx_ssl_sess_id_t           session_cache_head;
    ngx_ssl_sess_id_t           session_cache_tail;
} ngx_ssl_session_cache_t;



#define NGX_SSL_SSLv2    2
#define NGX_SSL_SSLv3    4
#define NGX_SSL_TLSv1    8


#define NGX_SSL_BUFFER   1
#define NGX_SSL_CLIENT   2

#define NGX_SSL_BUFSIZE  16384


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_generate_rsa512_key(ngx_ssl_t *ssl);
ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout);
ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);

ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
#define ngx_ssl_get_session(c)      SSL_get1_session(c->ssl->connection)
#define ngx_ssl_free_session        SSL_SESSION_free
#define ngx_ssl_get_connection(ssl_conn)                                      \
    SSL_get_ex_data(ssl_conn, ngx_ssl_connection_index)
#define ngx_ssl_get_server_conf(ssl_ctx)                                      \
    SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_server_conf_index)


ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);


ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


extern int  ngx_ssl_connection_index;
extern int  ngx_ssl_server_conf_index;
extern int  ngx_ssl_session_cache_index;


#endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
