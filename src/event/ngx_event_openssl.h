
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_OPENSSL_H_INCLUDED_
#define _NGX_EVENT_OPENSSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
#endif
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define NGX_SSL_NAME     "OpenSSL"


#if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
#undef OPENSSL_VERSION_NUMBER
#if (LIBRESSL_VERSION_NUMBER >= 0x3050000fL)
#define OPENSSL_VERSION_NUMBER  0x1010000fL
#else
#define OPENSSL_VERSION_NUMBER  0x1000107fL
#endif
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)

#define ngx_ssl_version()       OpenSSL_version(OPENSSL_VERSION)

#else

#define ngx_ssl_version()       SSLeay_version(SSLEAY_VERSION)

#endif


#define ngx_ssl_session_t       SSL_SESSION
#define ngx_ssl_conn_t          SSL


#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
#define SSL_is_server(s)        (s)->server
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined SSL_get_peer_certificate)
#define SSL_get_peer_certificate(s)  SSL_get1_peer_certificate(s)
#endif


#if (OPENSSL_VERSION_NUMBER < 0x30000000L && !defined ERR_peek_error_data)
#define ERR_peek_error_data(d, f)    ERR_peek_error_line_data(NULL, NULL, d, f)
#endif


#ifdef OPENSSL_NO_DEPRECATED_3_4
#define SSL_SESSION_get_time(s)      SSL_SESSION_get_time_ex(s)
#define SSL_SESSION_set_time(s, t)   SSL_SESSION_set_time_ex(s, t)
#endif


#ifdef OPENSSL_NO_DEPRECATED_3_0
#define EVP_CIPHER_CTX_cipher(c)     EVP_CIPHER_CTX_get0_cipher(c)
#endif


#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#define SSL_group_to_name(s, nid)    NULL
#endif


typedef struct ngx_ssl_ocsp_s   ngx_ssl_ocsp_t;


struct ngx_ssl_s {
    SSL_CTX                    *ctx;
    ngx_log_t                  *log;
    size_t                      buffer_size;

    ngx_array_t                 certs;

    ngx_rbtree_t                staple_rbtree;
    ngx_rbtree_node_t           staple_sentinel;
};


struct ngx_ssl_connection_s {
    ngx_ssl_conn_t             *connection;
    SSL_CTX                    *session_ctx;

    ngx_int_t                   last;
    ngx_buf_t                  *buf;
    size_t                      buffer_size;

    ngx_connection_handler_pt   handler;

    ngx_ssl_session_t          *session;
    ngx_connection_handler_pt   save_session;

    ngx_event_handler_pt        saved_read_handler;
    ngx_event_handler_pt        saved_write_handler;

    ngx_ssl_ocsp_t             *ocsp;

    u_char                      early_buf;

    unsigned                    handshaked:1;
    unsigned                    handshake_rejected:1;
    unsigned                    renegotiation:1;
    unsigned                    buffer:1;
    unsigned                    sendfile:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    shutdown_without_free:1;
    unsigned                    handshake_buffer_set:1;
    unsigned                    session_timeout_set:1;
    unsigned                    try_early_data:1;
    unsigned                    in_early:1;
    unsigned                    in_ocsp:1;
    unsigned                    early_preread:1;
    unsigned                    write_blocked:1;
    unsigned                    sni_accepted:1;
};


#define NGX_SSL_NO_SCACHE            -2
#define NGX_SSL_NONE_SCACHE          -3
#define NGX_SSL_NO_BUILTIN_SCACHE    -4
#define NGX_SSL_DFLT_BUILTIN_SCACHE  -5


#define NGX_SSL_MAX_SESSION_SIZE  8192

typedef struct ngx_ssl_sess_id_s  ngx_ssl_sess_id_t;

struct ngx_ssl_sess_id_s {
    ngx_rbtree_node_t           node;
    size_t                      len;
    ngx_queue_t                 queue;
    time_t                      expire;
    u_char                      id[32];
#if (NGX_PTR_SIZE == 8)
    u_char                     *session;
#else
    u_char                      session[1];
#endif
};


typedef struct {
    u_char                      name[16];
    u_char                      hmac_key[32];
    u_char                      aes_key[32];
    time_t                      expire;
    unsigned                    size:8;
    unsigned                    shared:1;
} ngx_ssl_ticket_key_t;


typedef struct {
    ngx_rbtree_t                session_rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 expire_queue;
    ngx_ssl_ticket_key_t        ticket_keys[3];
    time_t                      fail_time;
} ngx_ssl_session_cache_t;


typedef int (*ngx_ssl_servername_pt)(ngx_ssl_conn_t *, int *, void *);

typedef struct {
    ngx_ssl_servername_pt       servername;
} ngx_ssl_client_hello_arg;


#define NGX_SSL_SSLv2    0x0002
#define NGX_SSL_SSLv3    0x0004
#define NGX_SSL_TLSv1    0x0008
#define NGX_SSL_TLSv1_1  0x0010
#define NGX_SSL_TLSv1_2  0x0020
#define NGX_SSL_TLSv1_3  0x0040


#if (defined SSL_OP_NO_TLSv1_2 || defined SSL_OP_NO_TLSv1_3)
#define NGX_SSL_DEFAULT_PROTOCOLS  (NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3)
#else
#define NGX_SSL_DEFAULT_PROTOCOLS  (NGX_SSL_TLSv1|NGX_SSL_TLSv1_1)
#endif


#define NGX_SSL_BUFFER   1
#define NGX_SSL_CLIENT   2

#define NGX_SSL_BUFSIZE  16384


#define NGX_SSL_CACHE_CERT  0
#define NGX_SSL_CACHE_PKEY  1
#define NGX_SSL_CACHE_CRL   2
#define NGX_SSL_CACHE_CA    3

#define NGX_SSL_CACHE_INVALIDATE  0x80000000


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);

ngx_int_t ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
ngx_int_t ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_ssl_cache_t *cache,
    ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificate_compression(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable);

ngx_int_t ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
ngx_int_t ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone);
ngx_int_t ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);

ngx_int_t ngx_ssl_ocsp_validate(ngx_connection_t *c);
ngx_int_t ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s);
void ngx_ssl_ocsp_cleanup(ngx_connection_t *c);
ngx_int_t ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data);

ngx_ssl_cache_t *ngx_ssl_cache_init(ngx_pool_t *pool, ngx_uint_t max,
    time_t valid, time_t inactive);
void *ngx_ssl_cache_fetch(ngx_conf_t *cf, ngx_uint_t index, char **err,
    ngx_str_t *path, void *data);
void *ngx_ssl_cache_connection_fetch(ngx_ssl_cache_t *cache, ngx_pool_t *pool,
    ngx_uint_t index, char **err, ngx_str_t *path, void *data);

ngx_array_t *ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file);
ngx_array_t *ngx_ssl_preserve_passwords(ngx_conf_t *cf,
    ngx_array_t *passwords);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);
ngx_int_t ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable);
ngx_int_t ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *commands);

ngx_int_t ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable);
ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ngx_array_t *certificates, ssize_t builtin_session_cache,
    ngx_shm_zone_t *shm_zone, time_t timeout);
ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *paths);
ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);

void ngx_ssl_set_client_hello_callback(SSL_CTX *ssl_ctx,
    ngx_ssl_client_hello_arg *cb);
#ifdef SSL_CLIENT_HELLO_SUCCESS
int ngx_ssl_client_hello_callback(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg);
#elif defined OPENSSL_IS_BORINGSSL
enum ssl_select_cert_result_t ngx_ssl_select_certificate(
    const SSL_CLIENT_HELLO *client_hello);
#endif

ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);

void ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c);
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

ngx_int_t ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name);


ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);


ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
#if (NGX_DEBUG)
void ngx_ssl_handshake_log(ngx_connection_t *c);
#endif
ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
void ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_ssl_connection_error(ngx_connection_t *c, int sslerr, ngx_err_t err,
    char *text);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


extern int  ngx_ssl_connection_index;
extern int  ngx_ssl_server_conf_index;
extern int  ngx_ssl_session_cache_index;
extern int  ngx_ssl_ticket_keys_index;
extern int  ngx_ssl_ocsp_index;
extern int  ngx_ssl_index;
extern int  ngx_ssl_certificate_name_index;
extern int  ngx_ssl_client_hello_arg_index;


extern u_char  ngx_ssl_session_buffer[NGX_SSL_MAX_SESSION_SIZE];


#endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
