
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_OPENSSL_H_INCLUDED_
#define _NGX_EVENT_OPENSSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>

#define NGX_SSL_NAME     "OpenSSL"


#define ngx_ssl_session_t       SSL_SESSION
#define ngx_ssl_conn_t          SSL


typedef struct {
    SSL_CTX                    *ctx;
    ngx_log_t                  *log;
    size_t                      buffer_size;
} ngx_ssl_t;


typedef struct {
    ngx_ssl_conn_t             *connection;

    ngx_int_t                   last;
    ngx_buf_t                  *buf;
    size_t                      buffer_size;

    ngx_connection_handler_pt   handler;

    ngx_event_handler_pt        saved_read_handler;
    ngx_event_handler_pt        saved_write_handler;

    unsigned                    handshaked:1;
    unsigned                    renegotiation:1;
    unsigned                    buffer:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    handshake_buffer_set:1;
} ngx_ssl_connection_t;


#define NGX_SSL_NO_SCACHE            -2
#define NGX_SSL_NONE_SCACHE          -3
#define NGX_SSL_NO_BUILTIN_SCACHE    -4
#define NGX_SSL_DFLT_BUILTIN_SCACHE  -5


#define NGX_SSL_MAX_SESSION_SIZE  4096

typedef struct ngx_ssl_sess_id_s  ngx_ssl_sess_id_t;

struct ngx_ssl_sess_id_s {
    ngx_rbtree_node_t           node;
    u_char                     *id;
    size_t                      len;
    u_char                     *session;
    ngx_queue_t                 queue;
    time_t                      expire;
#if (NGX_PTR_SIZE == 8)
    void                       *stub;
    u_char                      sess_id[32];
#endif
};


typedef struct {
    ngx_rbtree_t                session_rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 expire_queue;
} ngx_ssl_session_cache_t;


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

typedef struct {
    u_char                      name[16];
    u_char                      aes_key[16];
    u_char                      hmac_key[16];
} ngx_ssl_session_ticket_key_t;

#endif


#define NGX_SSL_SSLv2    0x0002
#define NGX_SSL_SSLv3    0x0004
#define NGX_SSL_TLSv1    0x0008
#define NGX_SSL_TLSv1_1  0x0010
#define NGX_SSL_TLSv1_2  0x0020


#define NGX_SSL_BUFFER   1
#define NGX_SSL_CLIENT   2

#define NGX_SSL_BUFSIZE  16384


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
RSA *ngx_ssl_rsa512_key_callback(ngx_ssl_conn_t *ssl_conn, int is_export,
    int key_length);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);
ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout);
ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *paths);
ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);

void ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
#define ngx_ssl_get_session(c)      SSL_get1_session(c->ssl->connection)
#define ngx_ssl_free_session        SSL_SESSION_free
#define ngx_ssl_get_connection(ssl_conn)                                      \
    SSL_get_ex_data(ssl_conn, ngx_ssl_connection_index)
#define ngx_ssl_get_server_conf(ssl_ctx)                                      \
    SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_server_conf_index)

#define ngx_ssl_verify_error_optional(n)                                      \
    (n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT                              \
     || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN                             \
     || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY                     \
     || n == X509_V_ERR_CERT_UNTRUSTED                                        \
     || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)


ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);


ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
void ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


extern int  ngx_ssl_connection_index;
extern int  ngx_ssl_server_conf_index;
extern int  ngx_ssl_session_cache_index;
extern int  ngx_ssl_session_ticket_keys_index;
extern int  ngx_ssl_certificate_index;
extern int  ngx_ssl_stapling_index;


#endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
