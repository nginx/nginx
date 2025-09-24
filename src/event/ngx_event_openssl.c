
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_SSL_PASSWORD_BUFFER_SIZE  4096


typedef struct {
    ngx_uint_t  engine;   /* unsigned  engine:1; */
} ngx_openssl_conf_t;


static ngx_inline ngx_int_t ngx_ssl_cert_already_in_hash(void);
static int ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
static void ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where,
    int ret);
static int ngx_ssl_cmp_x509_name(const X509_NAME *const *a,
    const X509_NAME *const *b);
static void ngx_ssl_passwords_cleanup(void *data);
static int ngx_ssl_new_client_session(ngx_ssl_conn_t *ssl_conn,
    ngx_ssl_session_t *sess);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ngx_int_t ngx_ssl_try_early_data(ngx_connection_t *c);
#endif
static void ngx_ssl_handshake_handler(ngx_event_t *ev);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ssize_t ngx_ssl_recv_early(ngx_connection_t *c, u_char *buf,
    size_t size);
#endif
static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n);
static void ngx_ssl_write_handler(ngx_event_t *wev);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ssize_t ngx_ssl_write_early(ngx_connection_t *c, u_char *data,
    size_t size);
#endif
static ssize_t ngx_ssl_sendfile(ngx_connection_t *c, ngx_buf_t *file,
    size_t size);
static void ngx_ssl_read_handler(ngx_event_t *rev);
static void ngx_ssl_shutdown_handler(ngx_event_t *ev);
static void ngx_ssl_clear_error(ngx_log_t *log);

static ngx_int_t ngx_ssl_session_id_context(ngx_ssl_t *ssl,
    ngx_str_t *sess_ctx, ngx_array_t *certificates);
static int ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn,
    ngx_ssl_session_t *sess);
static ngx_ssl_session_t *ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy);
static void ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
static void ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n);
static void ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB
static int ngx_ssl_ticket_key_callback(ngx_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc);
static ngx_int_t ngx_ssl_rotate_ticket_keys(SSL_CTX *ssl_ctx, ngx_log_t *log);
static void ngx_ssl_ticket_keys_cleanup(void *data);
#endif

#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
static ngx_int_t ngx_ssl_check_name(ngx_str_t *name, ASN1_STRING *str);
#endif

static time_t ngx_ssl_parse_time(
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    const
#endif
    ASN1_TIME *asn1time, ngx_log_t *log);

static void *ngx_openssl_create_conf(ngx_cycle_t *cycle);
static char *ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_openssl_exit(ngx_cycle_t *cycle);


static ngx_command_t  ngx_openssl_commands[] = {

    { ngx_string("ssl_engine"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_openssl_engine,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_openssl_module_ctx = {
    ngx_string("openssl"),
    ngx_openssl_create_conf,
    NULL
};


ngx_module_t  ngx_openssl_module = {
    NGX_MODULE_V1,
    &ngx_openssl_module_ctx,               /* module context */
    ngx_openssl_commands,                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_openssl_exit,                      /* exit master */
    NGX_MODULE_V1_PADDING
};


int  ngx_ssl_connection_index;
int  ngx_ssl_server_conf_index;
int  ngx_ssl_session_cache_index;
int  ngx_ssl_ticket_keys_index;
int  ngx_ssl_ocsp_index;
int  ngx_ssl_index;
int  ngx_ssl_certificate_name_index;
int  ngx_ssl_client_hello_arg_index;


u_char  ngx_ssl_session_buffer[NGX_SSL_MAX_SESSION_SIZE];


ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
#if (OPENSSL_INIT_LOAD_CONFIG && !defined LIBRESSL_VERSION_NUMBER)

    uint64_t                opts;
    OPENSSL_INIT_SETTINGS  *init;

    opts = OPENSSL_INIT_LOAD_CONFIG;

#if (NGX_OPENSSL_NO_CONFIG)

    if (getenv("OPENSSL_CONF") == NULL) {
        opts = OPENSSL_INIT_NO_LOAD_CONFIG;
    }

#endif

    init = OPENSSL_INIT_new();
    if (init == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "OPENSSL_INIT_new() failed");
        return NGX_ERROR;
    }

#ifndef OPENSSL_NO_STDIO
    if (OPENSSL_INIT_set_config_appname(init, "nginx") == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "OPENSSL_INIT_set_config_appname() failed");
        return NGX_ERROR;
    }
#endif

    if (OPENSSL_init_ssl(opts, init) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "OPENSSL_init_ssl() failed");
        return NGX_ERROR;
    }

    OPENSSL_INIT_free(init);

    /*
     * OPENSSL_init_ssl() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

#else

#if (NGX_OPENSSL_NO_CONFIG)

    if (getenv("OPENSSL_CONF") == NULL) {
        OPENSSL_no_config();
    }

#endif

    OPENSSL_config("nginx");

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

#endif

#ifndef SSL_OP_NO_COMPRESSION
    {
    /*
     * Disable gzip compression in OpenSSL prior to 1.0.0 version,
     * this saves about 522K per connection.
     */
    int                  n;
    STACK_OF(SSL_COMP)  *ssl_comp_methods;

    ssl_comp_methods = SSL_COMP_get_compression_methods();
    n = sk_SSL_COMP_num(ssl_comp_methods);

    while (n--) {
        (void) sk_SSL_COMP_pop(ssl_comp_methods);
    }
    }
#endif

    ngx_ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (ngx_ssl_connection_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "SSL_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_server_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (ngx_ssl_server_conf_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_session_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);
    if (ngx_ssl_session_cache_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_ticket_keys_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (ngx_ssl_ticket_keys_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_ocsp_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ngx_ssl_ocsp_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (ngx_ssl_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_certificate_name_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);

    if (ngx_ssl_certificate_name_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_client_hello_arg_index = SSL_CTX_get_ex_new_index(0, NULL, NULL,
                                                              NULL, NULL);
    if (ngx_ssl_client_hello_arg_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
{
    ssl->ctx = SSL_CTX_new(SSLv23_method());

    if (ssl->ctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "SSL_CTX_new() failed");
        return NGX_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_server_conf_index, data) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_index, ssl) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    ngx_rbtree_init(&ssl->staple_rbtree, &ssl->staple_sentinel,
                    ngx_rbtree_insert_value);

    ssl->buffer_size = NGX_SSL_BUFSIZE;

    /* client side options */

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

    /* server side options */

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
    /* only in 0.9.8m+ */
    SSL_CTX_clear_options(ssl->ctx,
                          SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
#endif

    if (!(protocols & NGX_SSL_SSLv2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv2);
    }
    if (!(protocols & NGX_SSL_SSLv3)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv3);
    }
    if (!(protocols & NGX_SSL_TLSv1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1);
    }
#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    if (!(protocols & NGX_SSL_TLSv1_1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    if (!(protocols & NGX_SSL_TLSv1_2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_3
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
    if (!(protocols & NGX_SSL_TLSv1_3)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
    }
#endif

#ifdef SSL_CTX_set_min_proto_version
    SSL_CTX_set_min_proto_version(ssl->ctx, 0);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_2_VERSION);
#endif

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(ssl->ctx, 0);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_3_VERSION);
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_OP_NO_TX_CERTIFICATE_COMPRESSION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_RX_CERTIFICATE_COMPRESSION);
#endif

#ifdef SSL_OP_NO_ANTI_REPLAY
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_ANTI_REPLAY);
#endif

#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(ssl->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    SSL_CTX_set_info_callback(ssl->ctx, ngx_ssl_info_callback);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *certs,
    ngx_array_t *keys, ngx_array_t *passwords)
{
    ngx_str_t   *cert, *key;
    ngx_uint_t   i;

    cert = certs->elts;
    key = keys->elts;

    for (i = 0; i < certs->nelts; i++) {

        if (ngx_ssl_certificate(cf, ssl, &cert[i], &key[i], passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key, ngx_array_t *passwords)
{
    char            *err;
    X509            *x509, **elm;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;

    chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CERT, &err, cert, NULL);
    if (chain == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return NGX_ERROR;
    }

    x509 = sk_X509_shift(chain);

    if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }

    if (X509_set_ex_data(x509, ngx_ssl_certificate_name_index, cert->data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }

    if (ssl->certs.elts == NULL) {
        if (ngx_array_init(&ssl->certs, cf->pool, 1, sizeof(X509 *))
            != NGX_OK)
        {
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }
    }

    elm = ngx_array_push(&ssl->certs);
    if (elm == NULL) {
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }

    *elm = x509;

    /*
     * Note that x509 is not freed here, but will be instead freed in
     * ngx_ssl_cleanup_ctx().  This is because we need to preserve all
     * certificates to be able to iterate all of them through ssl->certs,
     * while OpenSSL can free a certificate if it is replaced with another
     * certificate of the same type.
     */

#ifdef SSL_CTX_set0_chain

    if (SSL_CTX_set0_chain(ssl->ctx, chain) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set0_chain(\"%s\") failed", cert->data);
        sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }

#else
    {
    int  n;

    /* SSL_CTX_set0_chain() is only available in OpenSSL 1.0.2+ */

    n = sk_X509_num(chain);

    while (n--) {
        x509 = sk_X509_shift(chain);

        if (SSL_CTX_add_extra_chain_cert(ssl->ctx, x509) == 0) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_add_extra_chain_cert(\"%s\") failed",
                          cert->data);
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }
    }

    sk_X509_free(chain);
    }
#endif

    pkey = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_PKEY, &err, key, passwords);
    if (pkey == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate key \"%s\": %s",
                          key->data, err);
        }

        return NGX_ERROR;
    }

    if (SSL_CTX_use_PrivateKey(ssl->ctx, pkey) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_PrivateKey(\"%s\") failed", key->data);
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }

    EVP_PKEY_free(pkey);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_ssl_cache_t *cache,
    ngx_array_t *passwords)
{
    char            *err;
    X509            *x509;
    u_long           n;
    EVP_PKEY        *pkey;
    ngx_uint_t       mask;
    STACK_OF(X509)  *chain;

    mask = 0;

retry:

    chain = ngx_ssl_cache_connection_fetch(cache, pool,
                                           NGX_SSL_CACHE_CERT | mask,
                                           &err, cert, NULL);
    if (chain == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return NGX_ERROR;
    }

    x509 = sk_X509_shift(chain);

    if (SSL_use_certificate(c->ssl->connection, x509) == 0) {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "SSL_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }

    X509_free(x509);

#ifdef SSL_set0_chain

    /*
     * SSL_set0_chain() is only available in OpenSSL 1.0.2+,
     * but this function is only called via certificate callback,
     * which is only available in OpenSSL 1.0.2+ as well
     */

    if (SSL_set0_chain(c->ssl->connection, chain) == 0) {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "SSL_set0_chain(\"%s\") failed", cert->data);
        sk_X509_pop_free(chain, X509_free);
        return NGX_ERROR;
    }

#endif

    pkey = ngx_ssl_cache_connection_fetch(cache, pool,
                                          NGX_SSL_CACHE_PKEY | mask,
                                          &err, key, passwords);
    if (pkey == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "cannot load certificate key \"%s\": %s",
                          key->data, err);
        }

        return NGX_ERROR;
    }

    if (SSL_use_PrivateKey(c->ssl->connection, pkey) == 0) {
        EVP_PKEY_free(pkey);

        /* there can be mismatched pairs on uneven cache update */

        n = ERR_peek_last_error();

        if (ERR_GET_LIB(n) == ERR_LIB_X509
            && ERR_GET_REASON(n) == X509_R_KEY_VALUES_MISMATCH
            && mask == 0)
        {
            ERR_clear_error();
            mask = NGX_SSL_CACHE_INVALIDATE;
            goto retry;
        }

        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "SSL_use_PrivateKey(\"%s\") failed", key->data);
        return NGX_ERROR;
    }

    EVP_PKEY_free(pkey);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificate_compression(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable)
{
    if (!enable) {
        return NGX_OK;
    }

#ifdef SSL_OP_NO_TX_CERTIFICATE_COMPRESSION

    if (SSL_CTX_compress_certs(ssl->ctx, 0) == 0) {
        ngx_ssl_error(NGX_LOG_WARN, ssl->log, 0,
                      "SSL_CTX_compress_certs() failed, ignored");
        return NGX_OK;
    }

    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);

#else

    ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                  "\"ssl_certificate_compression\" is not supported "
                  "on this platform, ignored");

#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers)
{
    if (SSL_CTX_set_cipher_list(ssl->ctx, (char *) ciphers->data) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      ciphers);
        return NGX_ERROR;
    }

    if (prefer_server_ciphers) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    int                   n, i;
    char                 *err;
    X509                 *x509;
    X509_NAME            *name;
    X509_STORE           *store;
    STACK_OF(X509)       *chain;
    STACK_OF(X509_NAME)  *list;

    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);

    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NGX_OK;
    }

    list = sk_X509_NAME_new(ngx_ssl_cmp_x509_name);
    if (list == NULL) {
        return NGX_ERROR;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NGX_ERROR;
    }

    chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CA, &err, cert, NULL);
    if (chain == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        sk_X509_NAME_pop_free(list, X509_NAME_free);
        return NGX_ERROR;
    }

    n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_value(chain, i);

        if (X509_STORE_add_cert(store, x509) != 1) {

            if (ngx_ssl_cert_already_in_hash()) {
                continue;
            }

            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "X509_STORE_add_cert(\"%s\") failed", cert->data);
            sk_X509_NAME_pop_free(list, X509_NAME_free);
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }

        name = X509_get_subject_name(x509);
        if (name == NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "X509_get_subject_name(\"%s\") failed", cert->data);
            sk_X509_NAME_pop_free(list, X509_NAME_free);
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }

        name = X509_NAME_dup(name);
        if (name == NULL) {
            sk_X509_NAME_pop_free(list, X509_NAME_free);
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }

#ifdef OPENSSL_IS_BORINGSSL
        if (sk_X509_NAME_find(list, NULL, name) > 0) {
#else
        if (sk_X509_NAME_find(list, name) >= 0) {
#endif
            X509_NAME_free(name);
            continue;
        }

        if (sk_X509_NAME_push(list, name) == 0) {
            sk_X509_NAME_pop_free(list, X509_NAME_free);
            sk_X509_pop_free(chain, X509_free);
            X509_NAME_free(name);
            return NGX_ERROR;
        }
    }

    sk_X509_pop_free(chain, X509_free);

    SSL_CTX_set_client_CA_list(ssl->ctx, list);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    int              i, n;
    char            *err;
    X509            *x509;
    X509_STORE      *store;
    STACK_OF(X509)  *chain;

    SSL_CTX_set_verify(ssl->ctx, SSL_CTX_get_verify_mode(ssl->ctx),
                       ngx_ssl_verify_callback);

    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NGX_OK;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NGX_ERROR;
    }

    chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CA, &err, cert, NULL);
    if (chain == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return NGX_ERROR;
    }

    n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_value(chain, i);

        if (X509_STORE_add_cert(store, x509) != 1) {

            if (ngx_ssl_cert_already_in_hash()) {
                continue;
            }

            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "X509_STORE_add_cert(\"%s\") failed", cert->data);
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }
    }

    sk_X509_pop_free(chain, X509_free);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    int                  n, i;
    char                *err;
    X509_CRL            *x509;
    X509_STORE          *store;
    STACK_OF(X509_CRL)  *chain;

    if (crl->len == 0) {
        return NGX_OK;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NGX_ERROR;
    }

    chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CRL, &err, crl, NULL);
    if (chain == NULL) {
        if (err != NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "cannot load CRL \"%s\": %s", crl->data, err);
        }

        return NGX_ERROR;
    }

    n = sk_X509_CRL_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_CRL_value(chain, i);

        if (X509_STORE_add_crl(store, x509) != 1) {

            if (ngx_ssl_cert_already_in_hash()) {
                continue;
            }

            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "X509_STORE_add_crl(\"%s\") failed", crl->data);
            sk_X509_CRL_pop_free(chain, X509_CRL_free);
            return NGX_ERROR;
        }
    }

    sk_X509_CRL_pop_free(chain, X509_CRL_free);

    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_ssl_cert_already_in_hash(void)
{
#if !(OPENSSL_VERSION_NUMBER >= 0x1010009fL \
      || LIBRESSL_VERSION_NUMBER >= 0x3050000fL)
    u_long  error;

    /*
     * OpenSSL prior to 1.1.0i doesn't ignore duplicate certificate entries,
     * see https://github.com/openssl/openssl/commit/c0452248
     */

    error = ERR_peek_last_error();

    if (ERR_GET_LIB(error) == ERR_LIB_X509
        && ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE)
    {
        ERR_clear_error();
        return 1;
    }
#endif

    return 0;
}


static int
ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
#if (NGX_DEBUG)
    char              *subject, *issuer;
    int                err, depth;
    X509              *cert;
    X509_NAME         *sname, *iname;
    ngx_connection_t  *c;
    ngx_ssl_conn_t    *ssl_conn;

    ssl_conn = X509_STORE_CTX_get_ex_data(x509_store,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());

    c = ngx_ssl_get_connection(ssl_conn);

    if (!(c->log->log_level & NGX_LOG_DEBUG_EVENT)) {
        return 1;
    }

    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);

    if (sname) {
        subject = X509_NAME_oneline(sname, NULL, 0);
        if (subject == NULL) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "X509_NAME_oneline() failed");
        }

    } else {
        subject = NULL;
    }

    iname = X509_get_issuer_name(cert);

    if (iname) {
        issuer = X509_NAME_oneline(iname, NULL, 0);
        if (issuer == NULL) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "X509_NAME_oneline() failed");
        }

    } else {
        issuer = NULL;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "verify:%d, error:%d, depth:%d, "
                   "subject:\"%s\", issuer:\"%s\"",
                   ok, err, depth,
                   subject ? subject : "(none)",
                   issuer ? issuer : "(none)");

    if (subject) {
        OPENSSL_free(subject);
    }

    if (issuer) {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}


static void
ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where, int ret)
{
    BIO               *rbio, *wbio;
    ngx_connection_t  *c;

#if (!defined SSL_OP_NO_RENEGOTIATION                                         \
     && !defined SSL_OP_NO_CLIENT_RENEGOTIATION)

    if ((where & SSL_CB_HANDSHAKE_START)
        && SSL_is_server((ngx_ssl_conn_t *) ssl_conn))
    {
        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

        if (c->ssl->handshaked) {
            c->ssl->renegotiation = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
        }
    }

#endif

#ifdef TLS1_3_VERSION

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP
        && SSL_version(ssl_conn) == TLS1_3_VERSION)
    {
        time_t        now, time, timeout, conf_timeout;
        SSL_SESSION  *sess;

        /*
         * OpenSSL with TLSv1.3 updates the session creation time on
         * session resumption and keeps the session timeout unmodified,
         * making it possible to maintain the session forever, bypassing
         * client certificate expiration and revocation.  To make sure
         * session timeouts are actually used, we now update the session
         * creation time and reduce the session timeout accordingly.
         *
         * BoringSSL with TLSv1.3 ignores configured session timeouts
         * and uses a hardcoded timeout instead, 7 days.  So we update
         * session timeout to the configured value as soon as a session
         * is created.
         */

        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
        sess = SSL_get0_session(ssl_conn);

        if (!c->ssl->session_timeout_set && sess) {
            c->ssl->session_timeout_set = 1;

            now = ngx_time();
            time = SSL_SESSION_get_time(sess);
            timeout = SSL_SESSION_get_timeout(sess);
            conf_timeout = SSL_CTX_get_timeout(c->ssl->session_ctx);

            timeout = ngx_min(timeout, conf_timeout);

            if (now - time >= timeout) {
                SSL_SESSION_set1_id_context(sess, (unsigned char *) "", 0);

            } else {
                SSL_SESSION_set_time(sess, now);
                SSL_SESSION_set_timeout(sess, timeout - (now - time));
            }
        }
    }

#endif

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

        if (!c->ssl->handshake_buffer_set) {
            /*
             * By default OpenSSL uses 4k buffer during a handshake,
             * which is too low for long certificate chains and might
             * result in extra round-trips.
             *
             * To adjust a buffer size we detect that buffering was added
             * to write side of the connection by comparing rbio and wbio.
             * If they are different, we assume that it's due to buffering
             * added to wbio, and set buffer size.
             */

            rbio = SSL_get_rbio(ssl_conn);
            wbio = SSL_get_wbio(ssl_conn);

            if (rbio != wbio) {
                (void) BIO_set_write_buffer_size(wbio, NGX_SSL_BUFSIZE);
                c->ssl->handshake_buffer_set = 1;
            }
        }
    }
}


static int
ngx_ssl_cmp_x509_name(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}


ngx_array_t *
ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file)
{
    u_char              *p, *last, *end;
    size_t               len;
    ssize_t              n;
    ngx_fd_t             fd;
    ngx_str_t           *pwd;
    ngx_array_t         *passwords;
    ngx_pool_cleanup_t  *cln;
    u_char               buf[NGX_SSL_PASSWORD_BUFFER_SIZE];

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NULL;
    }

    passwords = ngx_array_create(cf->temp_pool, 4, sizeof(ngx_str_t));
    if (passwords == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->temp_pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ssl_passwords_cleanup;
    cln->data = passwords;

    fd = ngx_open_file(file->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", file->data);
        return NULL;
    }

    len = 0;
    last = buf;

    do {
        n = ngx_read_fd(fd, last, NGX_SSL_PASSWORD_BUFFER_SIZE - len);

        if (n == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_read_fd_n " \"%s\" failed", file->data);
            passwords = NULL;
            goto cleanup;
        }

        end = last + n;

        if (len && n == 0) {
            *end++ = LF;
        }

        p = buf;

        for ( ;; ) {
            last = ngx_strlchr(last, end, LF);

            if (last == NULL) {
                break;
            }

            len = last++ - p;

            if (len && p[len - 1] == CR) {
                len--;
            }

            if (len) {
                pwd = ngx_array_push(passwords);
                if (pwd == NULL) {
                    passwords = NULL;
                    goto cleanup;
                }

                pwd->len = len;
                pwd->data = ngx_pnalloc(cf->temp_pool, len);

                if (pwd->data == NULL) {
                    passwords->nelts--;
                    passwords = NULL;
                    goto cleanup;
                }

                ngx_memcpy(pwd->data, p, len);
            }

            p = last;
        }

        len = end - p;

        if (len == NGX_SSL_PASSWORD_BUFFER_SIZE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "too long line in \"%s\"", file->data);
            passwords = NULL;
            goto cleanup;
        }

        ngx_memmove(buf, p, len);
        last = buf + len;

    } while (n != 0);

    if (passwords->nelts == 0) {
        pwd = ngx_array_push(passwords);
        if (pwd == NULL) {
            passwords = NULL;
            goto cleanup;
        }

        ngx_memzero(pwd, sizeof(ngx_str_t));
    }

cleanup:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%s\" failed", file->data);
    }

    ngx_explicit_memzero(buf, NGX_SSL_PASSWORD_BUFFER_SIZE);

    return passwords;
}


ngx_array_t *
ngx_ssl_preserve_passwords(ngx_conf_t *cf, ngx_array_t *passwords)
{
    ngx_str_t           *opwd, *pwd;
    ngx_uint_t           i;
    ngx_array_t         *pwds;
    ngx_pool_cleanup_t  *cln;
    static ngx_array_t   empty_passwords;

    if (passwords == NULL) {

        /*
         * If there are no passwords, an empty array is used
         * to make sure OpenSSL's default password callback
         * won't block on reading from stdin.
         */

        return &empty_passwords;
    }

    /*
     * Passwords are normally allocated from the temporary pool
     * and cleared after parsing configuration.  To be used at
     * runtime they have to be copied to the configuration pool.
     */

    pwds = ngx_array_create(cf->pool, passwords->nelts, sizeof(ngx_str_t));
    if (pwds == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ssl_passwords_cleanup;
    cln->data = pwds;

    opwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {

        pwd = ngx_array_push(pwds);
        if (pwd == NULL) {
            return NULL;
        }

        pwd->len = opwd[i].len;
        pwd->data = ngx_pnalloc(cf->pool, pwd->len);

        if (pwd->data == NULL) {
            pwds->nelts--;
            return NULL;
        }

        ngx_memcpy(pwd->data, opwd[i].data, opwd[i].len);
    }

    return pwds;
}


static void
ngx_ssl_passwords_cleanup(void *data)
{
    ngx_array_t *passwords = data;

    ngx_str_t   *pwd;
    ngx_uint_t   i;

    pwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {
        ngx_explicit_memzero(pwd[i].data, pwd[i].len);
    }
}


ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
#ifndef OPENSSL_NO_DH

    BIO  *bio;

    if (file->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "r");
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return NGX_ERROR;
    }

#ifdef SSL_CTX_set_tmp_dh
    {
    DH  *dh;

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (dh == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_DHparams(\"%s\") failed", file->data);
        BIO_free(bio);
        return NGX_ERROR;
    }

    if (SSL_CTX_set_tmp_dh(ssl->ctx, dh) != 1) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_tmp_dh(\"%s\") failed", file->data);
        DH_free(dh);
        BIO_free(bio);
        return NGX_ERROR;
    }

    DH_free(dh);
    }
#else
    {
    EVP_PKEY  *dh;

    /*
     * PEM_read_bio_DHparams() and SSL_CTX_set_tmp_dh()
     * are deprecated in OpenSSL 3.0
     */

    dh = PEM_read_bio_Parameters(bio, NULL);
    if (dh == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_Parameters(\"%s\") failed", file->data);
        BIO_free(bio);
        return NGX_ERROR;
    }

    if (SSL_CTX_set0_tmp_dh_pkey(ssl->ctx, dh) != 1) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set0_tmp_dh_pkey(\"%s\") failed", file->data);
#if (OPENSSL_VERSION_NUMBER >= 0x30000010L)
        EVP_PKEY_free(dh);
#endif
        BIO_free(bio);
        return NGX_ERROR;
    }
    }
#endif

    BIO_free(bio);

#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
{
#ifndef OPENSSL_NO_ECDH

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields.  OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

#if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)

    /*
     * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
     * curve previously supported.  By default an internal list is used,
     * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
     * and X25519 in OpenSSL 1.1.0+.
     *
     * By default a curve preferred by the client will be used for
     * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
     * be used to prefer server curves instead, similar to what it
     * does for ciphers.
     */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

#ifdef SSL_CTRL_SET_ECDH_AUTO
    /* not needed in OpenSSL 1.1.0+ */
    (void) SSL_CTX_set_ecdh_auto(ssl->ctx, 1);
#endif

    if (ngx_strcmp(name->data, "auto") == 0) {
        return NGX_OK;
    }

    if (SSL_CTX_set1_curves_list(ssl->ctx, (char *) name->data) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set1_curves_list(\"%s\") failed", name->data);
        return NGX_ERROR;
    }

#else

    int      nid;
    char    *curve;
    EC_KEY  *ecdh;

    if (ngx_strcmp(name->data, "auto") == 0) {
        curve = "prime256v1";

    } else {
        curve = (char *) name->data;
    }

    nid = OBJ_sn2nid(curve);
    if (nid == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "OBJ_sn2nid(\"%s\") failed: unknown curve", curve);
        return NGX_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "EC_KEY_new_by_curve_name(\"%s\") failed", curve);
        return NGX_ERROR;
    }

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ssl->ctx, ecdh);

    EC_KEY_free(ecdh);
#endif
#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
{
    if (!enable) {
        return NGX_OK;
    }

#ifdef SSL_ERROR_EARLY_DATA_REJECTED

    /* BoringSSL */

    SSL_CTX_set_early_data_enabled(ssl->ctx, 1);

#elif defined SSL_READ_EARLY_DATA_SUCCESS

    /* OpenSSL */

    SSL_CTX_set_max_early_data(ssl->ctx, NGX_SSL_BUFSIZE);

#else
    ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                  "\"ssl_early_data\" is not supported on this platform, "
                  "ignored");
#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *commands)
{
    if (commands == NULL) {
        return NGX_OK;
    }

#ifdef SSL_CONF_FLAG_FILE
    {
    int            type;
    u_char        *key, *value;
    ngx_uint_t     i;
    ngx_keyval_t  *cmd;
    SSL_CONF_CTX  *cctx;

    cctx = SSL_CONF_CTX_new();
    if (cctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CONF_CTX_new() failed");
        return NGX_ERROR;
    }

    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SHOW_ERRORS);

    SSL_CONF_CTX_set_ssl_ctx(cctx, ssl->ctx);

    cmd = commands->elts;
    for (i = 0; i < commands->nelts; i++) {

        key = cmd[i].key.data;
        type = SSL_CONF_cmd_value_type(cctx, (char *) key);

        if (type == SSL_CONF_TYPE_FILE || type == SSL_CONF_TYPE_DIR) {
            if (ngx_conf_full_name(cf->cycle, &cmd[i].value, 1) != NGX_OK) {
                SSL_CONF_CTX_free(cctx);
                return NGX_ERROR;
            }
        }

        value = cmd[i].value.data;

        if (SSL_CONF_cmd(cctx, (char *) key, (char *) value) <= 0) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "SSL_CONF_cmd(\"%s\", \"%s\") failed", key, value);
            SSL_CONF_CTX_free(cctx);
            return NGX_ERROR;
        }
    }

    if (SSL_CONF_CTX_finish(cctx) != 1) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CONF_finish() failed");
        SSL_CONF_CTX_free(cctx);
        return NGX_ERROR;
    }

    SSL_CONF_CTX_free(cctx);

    return NGX_OK;
    }
#else
    ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                  "SSL_CONF_cmd() is not available on this platform");
    return NGX_ERROR;
#endif
}


ngx_int_t
ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
{
    if (!enable) {
        return NGX_OK;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx,
                                   SSL_SESS_CACHE_CLIENT
                                   |SSL_SESS_CACHE_NO_INTERNAL);

    SSL_CTX_sess_set_new_cb(ssl->ctx, ngx_ssl_new_client_session);

    return NGX_OK;
}


static int
ngx_ssl_new_client_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->save_session) {
        c->ssl->session = sess;

        c->ssl->save_session(c);

        c->ssl->session = NULL;
    }

    return 0;
}


void
ngx_ssl_set_client_hello_callback(SSL_CTX *ssl_ctx,
    ngx_ssl_client_hello_arg *cb)
{
#ifdef SSL_CLIENT_HELLO_SUCCESS

    SSL_CTX_set_client_hello_cb(ssl_ctx, ngx_ssl_client_hello_callback, NULL);
    SSL_CTX_set_ex_data(ssl_ctx, ngx_ssl_client_hello_arg_index, cb);

#elif defined OPENSSL_IS_BORINGSSL

    SSL_CTX_set_select_certificate_cb(ssl_ctx, ngx_ssl_select_certificate);
    SSL_CTX_set_ex_data(ssl_ctx, ngx_ssl_client_hello_arg_index, cb);

#endif
}


#ifdef SSL_CLIENT_HELLO_SUCCESS

int
ngx_ssl_client_hello_callback(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    u_char                    *p;
    size_t                     len;
    ngx_int_t                  rc;
    ngx_str_t                  host;
    ngx_connection_t          *c;
    ngx_ssl_client_hello_arg  *cb;

    c = ngx_ssl_get_connection(ssl_conn);
    cb = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                             ngx_ssl_client_hello_arg_index);

    if (SSL_client_hello_get0_ext(ssl_conn, TLSEXT_TYPE_server_name,
                                  (const unsigned char **) &p, &len)
        == 0)
    {
        ngx_str_null(&host);
        goto done;
    }

    /*
     * RFC 6066 mandates non-zero HostName length, we follow OpenSSL.
     * No more than one ServerName is expected.
     */

    if (len < 5
        || (size_t) (p[0] << 8) + p[1] + 2 != len
        || p[2] != TLSEXT_NAMETYPE_host_name
        || (size_t) (p[3] << 8) + p[4] + 2 + 3 != len)
    {
        *ad = SSL_AD_DECODE_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    len -= 5;
    p += 5;

    if (len > TLSEXT_MAXLEN_host_name || ngx_strlchr(p, p + len, '\0')) {
        *ad = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_CLIENT_HELLO_ERROR;
    }

    host.len = len;
    host.data = p;

done:

    rc = cb->servername(ssl_conn, ad, &host);

    if (rc == SSL_TLSEXT_ERR_ALERT_FATAL) {
        return SSL_CLIENT_HELLO_ERROR;
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

#elif defined OPENSSL_IS_BORINGSSL

enum ssl_select_cert_result_t ngx_ssl_select_certificate(
    const SSL_CLIENT_HELLO *client_hello)
{
    int                        ad;
    ngx_int_t                  rc;
    ngx_ssl_conn_t            *ssl_conn;
    ngx_connection_t          *c;
    ngx_ssl_client_hello_arg  *cb;

    ssl_conn = client_hello->ssl;
    c = ngx_ssl_get_connection(ssl_conn);
    cb = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                             ngx_ssl_client_hello_arg_index);

    /*
     * BoringSSL sends a hardcoded "handshake_failure" alert on errors,
     * we use it to map SSL_AD_INTERNAL_ERROR.  To preserve other alert
     * values, error handling is postponed to the servername callback.
     */

    rc = cb->servername(ssl_conn, &ad, NULL);

    if (rc == SSL_TLSEXT_ERR_ALERT_FATAL && ad == SSL_AD_INTERNAL_ERROR) {
        return ssl_select_cert_error;
    }

    return ssl_select_cert_success;
}

#endif


ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_ssl_connection_t  *sc;

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->buffer = ((flags & NGX_SSL_BUFFER) != 0);
    sc->buffer_size = ssl->buffer_size;

    sc->session_ctx = ssl->ctx;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (SSL_CTX_get_max_early_data(ssl->ctx)) {
        sc->try_early_data = 1;
    }
#endif

    sc->connection = SSL_new(ssl->ctx);

    if (sc->connection == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return NGX_ERROR;
    }

    if (SSL_set_fd(sc->connection, c->fd) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
        return NGX_ERROR;
    }

    if (flags & NGX_SSL_CLIENT) {
        SSL_set_connect_state(sc->connection);

    } else {
        SSL_set_accept_state(sc->connection);

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(sc->connection, SSL_OP_NO_RENEGOTIATION);
#endif
    }

    if (SSL_set_ex_data(sc->connection, ngx_ssl_connection_index, c) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        return NGX_ERROR;
    }

    c->ssl = sc;

    return NGX_OK;
}


ngx_ssl_session_t *
ngx_ssl_get_session(ngx_connection_t *c)
{
#ifdef TLS1_3_VERSION
    if (c->ssl->session) {
        SSL_SESSION_up_ref(c->ssl->session);
        return c->ssl->session;
    }
#endif

    return SSL_get1_session(c->ssl->connection);
}


ngx_ssl_session_t *
ngx_ssl_get0_session(ngx_connection_t *c)
{
    if (c->ssl->session) {
        return c->ssl->session;
    }

    return SSL_get0_session(c->ssl->connection);
}


ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    if (session) {
        if (SSL_set_session(c->ssl->connection, session) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_session() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    int        n, sslerr;
    ngx_err_t  err;
    ngx_int_t  rc;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->try_early_data) {
        return ngx_ssl_try_early_data(c);
    }
#endif

    if (c->ssl->in_ocsp) {
        return ngx_ssl_ocsp_validate(c);
    }

    ngx_ssl_clear_error(c->log);

    n = SSL_do_handshake(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == 1) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        ngx_ssl_handshake_log(c);
#endif

        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;

        c->read->ready = 1;
        c->write->ready = 1;

#if (!defined SSL_OP_NO_RENEGOTIATION                                         \
     && !defined SSL_OP_NO_CLIENT_RENEGOTIATION                               \
     && defined SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS                             \
     && OPENSSL_VERSION_NUMBER < 0x10100000L)

        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
        if (c->ssl->connection->s3 && SSL_is_server(c->ssl->connection)) {
            c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }

#endif

#if (defined BIO_get_ktls_send && !NGX_WIN32)

        if (BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) == 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "BIO_get_ktls_send(): 1");
            c->ssl->sendfile = 1;
        }

#endif

        rc = ngx_ssl_ocsp_validate(c);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_AGAIN) {
            c->read->handler = ngx_ssl_handshake_handler;
            c->write->handler = ngx_ssl_handshake_handler;
            return NGX_AGAIN;
        }

        c->ssl->handshaked = 1;

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_connection_error(c, err,
                             "peer closed connection in SSL handshake");

        return NGX_ERROR;
    }

    if (c->ssl->handshake_rejected) {
        ngx_connection_error(c, err, "handshake rejected");
        ERR_clear_error();

        return NGX_ERROR;
    }

    c->read->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    return NGX_ERROR;
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static ngx_int_t
ngx_ssl_try_early_data(ngx_connection_t *c)
{
    int        n, sslerr;
    u_char     buf;
    size_t     readbytes;
    ngx_err_t  err;
    ngx_int_t  rc;

    ngx_ssl_clear_error(c->log);

    readbytes = 0;

    n = SSL_read_early_data(c->ssl->connection, &buf, 1, &readbytes);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_read_early_data: %d, %uz", n, readbytes);

    if (n == SSL_READ_EARLY_DATA_FINISH) {
        c->ssl->try_early_data = 0;
        return ngx_ssl_handshake(c);
    }

    if (n == SSL_READ_EARLY_DATA_SUCCESS) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        ngx_ssl_handshake_log(c);
#endif

        c->ssl->try_early_data = 0;

        c->ssl->early_buf = buf;
        c->ssl->early_preread = 1;

        c->ssl->in_early = 1;

        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;

        c->read->ready = 1;
        c->write->ready = 1;

#if (defined BIO_get_ktls_send && !NGX_WIN32)

        if (BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) == 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "BIO_get_ktls_send(): 1");
            c->ssl->sendfile = 1;
        }

#endif

        rc = ngx_ssl_ocsp_validate(c);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_AGAIN) {
            c->read->handler = ngx_ssl_handshake_handler;
            c->write->handler = ngx_ssl_handshake_handler;
            return NGX_AGAIN;
        }

        c->ssl->handshaked = 1;

        return NGX_OK;
    }

    /* SSL_READ_EARLY_DATA_ERROR */

    sslerr = SSL_get_error(c->ssl->connection, n);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_connection_error(c, err,
                             "peer closed connection in SSL handshake");

        return NGX_ERROR;
    }

    c->read->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_read_early_data() failed");

    return NGX_ERROR;
}

#endif


#if (NGX_DEBUG)

void
ngx_ssl_handshake_log(ngx_connection_t *c)
{
    char         buf[129], *s, *d;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    const
#endif
    SSL_CIPHER  *cipher;

    if (!(c->log->log_level & NGX_LOG_DEBUG_EVENT)) {
        return;
    }

    cipher = SSL_get_current_cipher(c->ssl->connection);

    if (cipher) {
        SSL_CIPHER_description(cipher, &buf[1], 128);

        for (s = &buf[1], d = buf; *s; s++) {
            if (*s == ' ' && *d == ' ') {
                continue;
            }

            if (*s == LF || *s == CR) {
                continue;
            }

            *++d = *s;
        }

        if (*d != ' ') {
            d++;
        }

        *d = '\0';

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL: %s, cipher: \"%s\"",
                       SSL_get_version(c->ssl->connection), &buf[1]);

        if (SSL_session_reused(c->ssl->connection)) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL reused session");
        }

    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL no shared ciphers");
    }
}

#endif


static void
ngx_ssl_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake handler: %d", ev->write);

    if (ev->timedout) {
        c->ssl->handler(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}


ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
{
    u_char     *last;
    ssize_t     n, bytes, size;
    ngx_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {
        size = b->end - last;

        if (limit) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        n = ngx_ssl_recv(c, last, size);

        if (n > 0) {
            last += n;
            bytes += n;

            if (!c->read->ready) {
                return bytes;
            }

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == NGX_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}


ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->in_early) {
        return ngx_ssl_recv_early(c, buf, size);
    }
#endif

    if (c->ssl->last == NGX_ERROR) {
        c->read->ready = 0;
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    ngx_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(c->ssl->connection, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n);

        if (c->ssl->last == NGX_OK) {

            size -= n;

            if (size == 0) {
                c->read->ready = 1;

                if (c->read->available >= 0) {
                    c->read->available -= bytes;

                    /*
                     * there can be data buffered at SSL layer,
                     * so we post an event to continue reading on the next
                     * iteration of the event loop
                     */

                    if (c->read->available < 0) {
                        c->read->available = 0;
                        c->read->ready = 0;

                        if (c->read->posted) {
                            ngx_delete_posted_event(c->read);
                        }

                        ngx_post_event(c->read, &ngx_posted_next_events);
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

                } else {

#if (NGX_HAVE_FIONREAD)

                    if (ngx_socket_nread(c->fd, &c->read->available) == -1) {
                        c->read->ready = 0;
                        c->read->error = 1;
                        ngx_connection_error(c, ngx_socket_errno,
                                             ngx_socket_nread_n " failed");
                        return NGX_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

#endif
                }

                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            if (c->ssl->last != NGX_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->ready = 0;
            c->read->error = 1;

            /* fall through */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static ssize_t
ngx_ssl_recv_early(ngx_connection_t *c, u_char *buf, size_t size)
{
    int        n, bytes;
    size_t     readbytes;

    if (c->ssl->last == NGX_ERROR) {
        c->read->ready = 0;
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    ngx_ssl_clear_error(c->log);

    if (c->ssl->early_preread) {

        if (size == 0) {
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;
        }

        *buf = c->ssl->early_buf;

        c->ssl->early_preread = 0;

        bytes = 1;
        size -= 1;
        buf += 1;
    }

    if (c->ssl->write_blocked) {
        return NGX_AGAIN;
    }

    /*
     * SSL_read_early_data() may return data in parts, so try to read
     * until SSL_read_early_data() would return no data
     */

    for ( ;; ) {

        readbytes = 0;

        n = SSL_read_early_data(c->ssl->connection, buf, size, &readbytes);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read_early_data: %d, %uz", n, readbytes);

        if (n == SSL_READ_EARLY_DATA_SUCCESS) {

            c->ssl->last = ngx_ssl_handle_recv(c, 1);

            bytes += readbytes;
            size -= readbytes;

            if (size == 0) {
                c->read->ready = 1;
                return bytes;
            }

            buf += readbytes;

            continue;
        }

        if (n == SSL_READ_EARLY_DATA_FINISH) {

            c->ssl->last = ngx_ssl_handle_recv(c, 1);
            c->ssl->in_early = 0;

            if (bytes) {
                c->read->ready = 1;
                return bytes;
            }

            return ngx_ssl_recv(c, buf, size);
        }

        /* SSL_READ_EARLY_DATA_ERROR */

        c->ssl->last = ngx_ssl_handle_recv(c, 0);

        if (bytes) {
            if (c->ssl->last != NGX_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->ready = 0;
            c->read->error = 1;

            /* fall through */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }
}

#endif


static ngx_int_t
ngx_ssl_handle_recv(ngx_connection_t *c, int n)
{
    int        sslerr;
    ngx_err_t  err;

#if (!defined SSL_OP_NO_RENEGOTIATION                                         \
     && !defined SSL_OP_NO_CLIENT_RENEGOTIATION)

    if (c->ssl->renegotiation) {
        /*
         * disable renegotiation (CVE-2009-3555):
         * OpenSSL (at least up to 0.9.8l) does not handle disabled
         * renegotiation gracefully, so drop connection here
         */

        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "SSL renegotiation disabled");

        while (ERR_peek_error()) {
            ngx_ssl_error(NGX_LOG_DEBUG, c->log, 0,
                          "ignoring stale global SSL error");
        }

        ERR_clear_error();

        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        return NGX_ERROR;
    }

#endif

    if (n > 0) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read: want write");

        c->write->ready = 0;

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = ngx_ssl_write_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "peer shutdown SSL cleanly");
        return NGX_DONE;
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_read() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL write handler");

    c->read->handler(c->read);
}


/*
 * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
 * before the SSL_write() call to decrease a SSL overhead.
 *
 * Besides for protocols such as HTTP it is possible to always buffer
 * the output to decrease a SSL overhead some more.
 */

ngx_chain_t *
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int           n;
    ngx_uint_t    flush;
    ssize_t       send, size, file_size;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;

    if (!c->ssl->buffer) {

        while (in) {
            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }


    /* the maximum limit size is the maximum int32_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_INT32_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_INT32_VALUE - ngx_pagesize;
    }

    buf = c->ssl->buf;

    if (buf == NULL) {
        buf = ngx_create_temp_buf(c->pool, c->ssl->buffer_size);
        if (buf == NULL) {
            return NGX_CHAIN_ERROR;
        }

        c->ssl->buf = buf;
    }

    if (buf->start == NULL) {
        buf->start = ngx_palloc(c->pool, c->ssl->buffer_size);
        if (buf->start == NULL) {
            return NGX_CHAIN_ERROR;
        }

        buf->pos = buf->start;
        buf->last = buf->start;
        buf->end = buf->start + c->ssl->buffer_size;
    }

    send = buf->last - buf->pos;
    flush = (in == NULL) ? 1 : buf->flush;

    for ( ;; ) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            if (in->buf->in_file && c->ssl->sendfile) {
                flush = 1;
                break;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %z", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (!flush && send < limit && buf->last < buf->end) {
            break;
        }

        size = buf->last - buf->pos;

        if (size == 0) {

            if (in && in->buf->in_file && send < limit) {

                /* coalesce the neighbouring file bufs */

                cl = in;
                file_size = (size_t) ngx_chain_coalesce_file(&cl, limit - send);

                n = ngx_ssl_sendfile(c, in->buf, file_size);

                if (n == NGX_ERROR) {
                    return NGX_CHAIN_ERROR;
                }

                if (n == NGX_AGAIN) {
                    break;
                }

                in = ngx_chain_update_sent(in, n);

                send += n;
                flush = 0;

                continue;
            }

            buf->flush = 0;
            c->buffered &= ~NGX_SSL_BUFFERED;

            return in;
        }

        n = ngx_ssl_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        buf->pos += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send >= limit) {
            break;
        }
    }

    buf->flush = flush;

    if (buf->pos < buf->last) {
        c->buffered |= NGX_SSL_BUFFERED;

    } else {
        c->buffered &= ~NGX_SSL_BUFFERED;
    }

    return in;
}


ssize_t
ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    ngx_err_t  err;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->in_early) {
        return ngx_ssl_write_early(c, data, size);
    }
#endif

    ngx_ssl_clear_error(c->log);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    n = SSL_write(c->ssl->connection, data, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        c->sent += n;

        return n;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    if (sslerr == SSL_ERROR_ZERO_RETURN) {

        /*
         * OpenSSL 1.1.1 fails to return SSL_ERROR_SYSCALL if an error
         * happens during SSL_write() after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead,
         * https://git.openssl.org/?p=openssl.git;a=commitdiff;h=8051ab2
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write: want read");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_write() failed");

    return NGX_ERROR;
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static ssize_t
ngx_ssl_write_early(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    size_t     written;
    ngx_err_t  err;

    ngx_ssl_clear_error(c->log);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    written = 0;

    n = SSL_write_early_data(c->ssl->connection, data, size, &written);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_write_early_data: %d, %uz", n, written);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        if (c->ssl->write_blocked) {
            c->ssl->write_blocked = 0;
            ngx_post_event(c->read, &ngx_posted_events);
        }

        c->sent += written;

        return written;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write_early_data: want write");

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        /*
         * OpenSSL 1.1.1a fails to handle SSL_read_early_data()
         * if an SSL_write_early_data() call blocked on writing,
         * see https://github.com/openssl/openssl/issues/7757
         */

        c->ssl->write_blocked = 1;

        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write_early_data: want read");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_write_early_data() failed");

    return NGX_ERROR;
}

#endif


static ssize_t
ngx_ssl_sendfile(ngx_connection_t *c, ngx_buf_t *file, size_t size)
{
#if (defined BIO_get_ktls_send && !NGX_WIN32)

    int        sslerr, flags;
    ssize_t    n;
    ngx_err_t  err;

    ngx_ssl_clear_error(c->log);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL to sendfile: @%O %uz",
                   file->file_pos, size);

    ngx_set_errno(0);

#if (NGX_HAVE_SENDFILE_NODISKIO)

    flags = (c->busy_count <= 2) ? SF_NODISKIO : 0;

    if (file->file->directio) {
        flags |= SF_NOCACHE;
    }

#else
    flags = 0;
#endif

    n = SSL_sendfile(c->ssl->connection, file->file->fd, file->file_pos,
                     size, flags);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_sendfile: %z", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

#if (NGX_HAVE_SENDFILE_NODISKIO)
        c->busy_count = 0;
#endif

        c->sent += n;

        return n;
    }

    if (n == 0) {

        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "SSL_sendfile() reported that \"%s\" was truncated at %O",
                      file->file->name.data, file->file_pos);

        return NGX_ERROR;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    if (sslerr == SSL_ERROR_ZERO_RETURN) {

        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens during writing after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    if (sslerr == SSL_ERROR_SSL
        && ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNINITIALIZED
        && ngx_errno != 0)
    {
        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens in sendfile(), and returns SSL_ERROR_SSL with
         * SSL_R_UNINITIALIZED reason instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

#if (NGX_HAVE_SENDFILE_NODISKIO)

        if (ngx_errno == EBUSY) {
            c->busy_count++;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL_sendfile() busy, count:%d", c->busy_count);

            if (c->write->posted) {
                ngx_delete_posted_event(c->write);
            }

            ngx_post_event(c->write, &ngx_posted_next_events);
        }

#endif

        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_sendfile: want read");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_sendfile() failed");

#else
    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "SSL_sendfile() not available");
#endif

    return NGX_ERROR;
}


static void
ngx_ssl_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL read handler");

    c->write->handler(c->write);
}


void
ngx_ssl_free_buffer(ngx_connection_t *c)
{
    if (c->ssl->buf && c->ssl->buf->start) {
        if (ngx_pfree(c->pool, c->ssl->buf->start) == NGX_OK) {
            c->ssl->buf->start = NULL;
        }
    }
}


ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    int         n, sslerr, mode;
    ngx_int_t   rc;
    ngx_err_t   err;
    ngx_uint_t  tries;

#if (NGX_QUIC)
    if (c->quic) {
        /* QUIC streams inherit SSL object */
        return NGX_OK;
    }
#endif

    rc = NGX_OK;

    ngx_ssl_ocsp_cleanup(c);

    if (SSL_in_init(c->ssl->connection)) {
        /*
         * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
         * an SSL handshake, while previous versions always return 0.
         * Avoid calling SSL_shutdown() if handshake wasn't completed.
         */

        goto done;
    }

    if (c->timedout || c->error || c->buffered) {
        mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;
        SSL_set_quiet_shutdown(c->ssl->connection, 1);

    } else {
        mode = SSL_get_shutdown(c->ssl->connection);

        if (c->ssl->no_wait_shutdown) {
            mode |= SSL_RECEIVED_SHUTDOWN;
        }

        if (c->ssl->no_send_shutdown) {
            mode |= SSL_SENT_SHUTDOWN;
        }

        if (c->ssl->no_wait_shutdown && c->ssl->no_send_shutdown) {
            SSL_set_quiet_shutdown(c->ssl->connection, 1);
        }
    }

    SSL_set_shutdown(c->ssl->connection, mode);

    ngx_ssl_clear_error(c->log);

    tries = 2;

    for ( ;; ) {

        /*
         * For bidirectional shutdown, SSL_shutdown() needs to be called
         * twice: first call sends the "close notify" alert and returns 0,
         * second call waits for the peer's "close notify" alert.
         */

        n = SSL_shutdown(c->ssl->connection);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

        if (n == 1) {
            goto done;
        }

        if (n == 0 && tries-- > 1) {
            continue;
        }

        /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */

        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);

        if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
            c->read->handler = ngx_ssl_shutdown_handler;
            c->write->handler = ngx_ssl_shutdown_handler;

            if (sslerr == SSL_ERROR_WANT_READ) {
                c->read->ready = 0;

            } else {
                c->write->ready = 0;
            }

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                goto failed;
            }

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                goto failed;
            }

            ngx_add_timer(c->read, 3000);

            return NGX_AGAIN;
        }

        if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
            goto done;
        }

        err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

        ngx_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");

        break;
    }

failed:

    rc = NGX_ERROR;

done:

    if (c->ssl->shutdown_without_free) {
        c->ssl->shutdown_without_free = 0;
        c->recv = ngx_recv;
        return rc;
    }

    SSL_free(c->ssl->connection);
    c->ssl = NULL;
    c->recv = ngx_recv;

    return rc;
}


static void
ngx_ssl_shutdown_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_connection_handler_pt   handler;

    c = ev->data;
    handler = c->ssl->handler;

    if (ev->timedout) {
        c->timedout = 1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "SSL shutdown handler");

    if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
        return;
    }

    handler(c);
}


void
ngx_ssl_connection_error(ngx_connection_t *c, int sslerr, ngx_err_t err,
    char *text)
{
    int         n;
    ngx_uint_t  level;

    level = NGX_LOG_CRIT;

    if (sslerr == SSL_ERROR_SYSCALL) {

        if (err == NGX_ECONNRESET
#if (NGX_WIN32)
            || err == NGX_ECONNABORTED
#endif
            || err == NGX_EPIPE
            || err == NGX_ENOTCONN
            || err == NGX_ETIMEDOUT
            || err == NGX_ECONNREFUSED
            || err == NGX_ENETDOWN
            || err == NGX_ENETUNREACH
            || err == NGX_EHOSTDOWN
            || err == NGX_EHOSTUNREACH)
        {
            switch (c->log_error) {

            case NGX_ERROR_IGNORE_ECONNRESET:
            case NGX_ERROR_INFO:
                level = NGX_LOG_INFO;
                break;

            case NGX_ERROR_ERR:
                level = NGX_LOG_ERR;
                break;

            default:
                break;
            }
        }

    } else if (sslerr == SSL_ERROR_SSL) {

        n = ERR_GET_REASON(ERR_peek_last_error());

            /* handshake failures */
        if (n == SSL_R_BAD_CHANGE_CIPHER_SPEC                        /*  103 */
#ifdef SSL_R_NO_SUITABLE_KEY_SHARE
            || n == SSL_R_NO_SUITABLE_KEY_SHARE                      /*  101 */
#endif
#ifdef SSL_R_BAD_ALERT
            || n == SSL_R_BAD_ALERT                                  /*  102 */
#endif
#ifdef SSL_R_BAD_KEY_SHARE
            || n == SSL_R_BAD_KEY_SHARE                              /*  108 */
#endif
#ifdef SSL_R_BAD_EXTENSION
            || n == SSL_R_BAD_EXTENSION                              /*  110 */
#endif
            || n == SSL_R_BAD_DIGEST_LENGTH                          /*  111 */
#ifdef SSL_R_MISSING_SIGALGS_EXTENSION
            || n == SSL_R_MISSING_SIGALGS_EXTENSION                  /*  112 */
#endif
            || n == SSL_R_BAD_PACKET_LENGTH                          /*  115 */
#ifdef SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM
            || n == SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            /*  118 */
#endif
#ifdef SSL_R_BAD_KEY_UPDATE
            || n == SSL_R_BAD_KEY_UPDATE                             /*  122 */
#endif
            || n == SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  /*  129 */
            || n == SSL_R_CCS_RECEIVED_EARLY                         /*  133 */
#ifdef SSL_R_DECODE_ERROR
            || n == SSL_R_DECODE_ERROR                               /*  137 */
#endif
#ifdef SSL_R_DATA_BETWEEN_CCS_AND_FINISHED
            || n == SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              /*  145 */
#endif
            || n == SSL_R_DATA_LENGTH_TOO_LONG                       /*  146 */
            || n == SSL_R_DIGEST_CHECK_FAILED                        /*  149 */
            || n == SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  /*  150 */
            || n == SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              /*  151 */
            || n == SSL_R_EXCESSIVE_MESSAGE_SIZE                     /*  152 */
#ifdef SSL_R_GOT_A_FIN_BEFORE_A_CCS
            || n == SSL_R_GOT_A_FIN_BEFORE_A_CCS                     /*  154 */
#endif
            || n == SSL_R_HTTPS_PROXY_REQUEST                        /*  155 */
            || n == SSL_R_HTTP_REQUEST                               /*  156 */
            || n == SSL_R_LENGTH_MISMATCH                            /*  159 */
#ifdef SSL_R_LENGTH_TOO_SHORT
            || n == SSL_R_LENGTH_TOO_SHORT                           /*  160 */
#endif
#ifdef SSL_R_NO_RENEGOTIATION
            || n == SSL_R_NO_RENEGOTIATION                           /*  182 */
#endif
#ifdef SSL_R_NO_CIPHERS_PASSED
            || n == SSL_R_NO_CIPHERS_PASSED                          /*  182 */
#endif
            || n == SSL_R_NO_CIPHERS_SPECIFIED                       /*  183 */
#ifdef SSL_R_BAD_CIPHER
            || n == SSL_R_BAD_CIPHER                                 /*  186 */
#endif
            || n == SSL_R_NO_COMPRESSION_SPECIFIED                   /*  187 */
            || n == SSL_R_NO_SHARED_CIPHER                           /*  193 */
#ifdef SSL_R_PACKET_LENGTH_TOO_LONG
            || n == SSL_R_PACKET_LENGTH_TOO_LONG                     /*  198 */
#endif
            || n == SSL_R_RECORD_LENGTH_MISMATCH                     /*  213 */
#ifdef SSL_R_TOO_MANY_WARNING_ALERTS
            || n == SSL_R_TOO_MANY_WARNING_ALERTS                    /*  220 */
#endif
#ifdef SSL_R_CLIENTHELLO_TLSEXT
            || n == SSL_R_CLIENTHELLO_TLSEXT                         /*  226 */
#endif
#ifdef SSL_R_PARSE_TLSEXT
            || n == SSL_R_PARSE_TLSEXT                               /*  227 */
#endif
#ifdef SSL_R_CALLBACK_FAILED
            || n == SSL_R_CALLBACK_FAILED                            /*  234 */
#endif
#ifdef SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG
            || n == SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG    /*  234 */
#endif
#ifdef SSL_R_NO_APPLICATION_PROTOCOL
            || n == SSL_R_NO_APPLICATION_PROTOCOL                    /*  235 */
#endif
            || n == SSL_R_UNEXPECTED_MESSAGE                         /*  244 */
            || n == SSL_R_UNEXPECTED_RECORD                          /*  245 */
            || n == SSL_R_UNKNOWN_ALERT_TYPE                         /*  246 */
            || n == SSL_R_UNKNOWN_PROTOCOL                           /*  252 */
#ifdef SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS
            || n == SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS             /*  253 */
#endif
#ifdef SSL_R_INVALID_COMPRESSION_LIST
            || n == SSL_R_INVALID_COMPRESSION_LIST                   /*  256 */
#endif
#ifdef SSL_R_MISSING_KEY_SHARE
            || n == SSL_R_MISSING_KEY_SHARE                          /*  258 */
#endif
            || n == SSL_R_UNSUPPORTED_PROTOCOL                       /*  258 */
#ifdef SSL_R_NO_SHARED_GROUP
            || n == SSL_R_NO_SHARED_GROUP                            /*  266 */
#endif
            || n == SSL_R_WRONG_VERSION_NUMBER                       /*  267 */
#ifdef SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA
            || n == SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA                /*  270 */
#endif
            || n == SSL_R_BAD_LENGTH                                 /*  271 */
            || n == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        /*  281 */
#ifdef SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY
            || n == SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY        /*  291 */
#endif
#ifdef SSL_R_APPLICATION_DATA_ON_SHUTDOWN
            || n == SSL_R_APPLICATION_DATA_ON_SHUTDOWN               /*  291 */
#endif
#ifdef SSL_R_BAD_LEGACY_VERSION
            || n == SSL_R_BAD_LEGACY_VERSION                         /*  292 */
#endif
#ifdef SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA
            || n == SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA     /*  293 */
#endif
#ifdef SSL_R_RECORD_TOO_SMALL
            || n == SSL_R_RECORD_TOO_SMALL                           /*  298 */
#endif
#ifdef SSL_R_SSL3_SESSION_ID_TOO_LONG
            || n == SSL_R_SSL3_SESSION_ID_TOO_LONG                   /*  300 */
#endif
#ifdef SSL_R_BAD_ECPOINT
            || n == SSL_R_BAD_ECPOINT                                /*  306 */
#endif
#ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
            || n == SSL_R_RENEGOTIATE_EXT_TOO_LONG                   /*  335 */
            || n == SSL_R_RENEGOTIATION_ENCODING_ERR                 /*  336 */
            || n == SSL_R_RENEGOTIATION_MISMATCH                     /*  337 */
#endif
#ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
            || n == SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       /*  338 */
#endif
#ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
            || n == SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           /*  345 */
#endif
#ifdef SSL_R_INAPPROPRIATE_FALLBACK
            || n == SSL_R_INAPPROPRIATE_FALLBACK                     /*  373 */
#endif
#ifdef SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS
            || n == SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             /*  376 */
#endif
#ifdef SSL_R_NO_SHARED_SIGATURE_ALGORITHMS
            || n == SSL_R_NO_SHARED_SIGATURE_ALGORITHMS              /*  376 */
#endif
#ifdef SSL_R_CERT_CB_ERROR
            || n == SSL_R_CERT_CB_ERROR                              /*  377 */
#endif
#ifdef SSL_R_VERSION_TOO_LOW
            || n == SSL_R_VERSION_TOO_LOW                            /*  396 */
#endif
#ifdef SSL_R_TOO_MANY_WARN_ALERTS
            || n == SSL_R_TOO_MANY_WARN_ALERTS                       /*  409 */
#endif
#ifdef SSL_R_BAD_RECORD_TYPE
            || n == SSL_R_BAD_RECORD_TYPE                            /*  443 */
#endif
            || n == 1000 /* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
#ifdef SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE
            || n == SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             /* 1010 */
            || n == SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 /* 1020 */
            || n == SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              /* 1021 */
            || n == SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                /* 1022 */
            || n == SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          /* 1030 */
            || n == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              /* 1040 */
            || n == SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 /* 1041 */
            || n == SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                /* 1042 */
            || n == SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        /* 1043 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            /* 1044 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            /* 1045 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            /* 1046 */
            || n == SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              /* 1047 */
            || n == SSL_R_TLSV1_ALERT_UNKNOWN_CA                     /* 1048 */
            || n == SSL_R_TLSV1_ALERT_ACCESS_DENIED                  /* 1049 */
            || n == SSL_R_TLSV1_ALERT_DECODE_ERROR                   /* 1050 */
            || n == SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  /* 1051 */
            || n == SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             /* 1060 */
            || n == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               /* 1070 */
            || n == SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          /* 1071 */
            || n == SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 /* 1080 */
            || n == SSL_R_TLSV1_ALERT_USER_CANCELLED                 /* 1090 */
            || n == SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               /* 1100 */
#endif
            )
        {
            switch (c->log_error) {

            case NGX_ERROR_IGNORE_ECONNRESET:
            case NGX_ERROR_INFO:
                level = NGX_LOG_INFO;
                break;

            case NGX_ERROR_ERR:
                level = NGX_LOG_ERR;
                break;

            default:
                break;
            }
        }
    }

    ngx_ssl_error(level, c->log, err, text);
}


static void
ngx_ssl_clear_error(ngx_log_t *log)
{
    while (ERR_peek_error()) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "ignoring stale global SSL error");
    }

    ERR_clear_error();
}


void ngx_cdecl
ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
{
    int          flags;
    u_long       n;
    va_list      args;
    u_char      *p, *last;
    u_char       errstr[NGX_MAX_CONF_ERRSTR];
    const char  *data;

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    if (ERR_peek_error()) {
        p = ngx_cpystrn(p, (u_char *) " (SSL:", last - p);

        for ( ;; ) {

            n = ERR_peek_error_data(&data, &flags);

            if (n == 0) {
                break;
            }

            /* ERR_error_string_n() requires at least one byte */

            if (p >= last - 1) {
                goto next;
            }

            *p++ = ' ';

            ERR_error_string_n(n, (char *) p, last - p);

            while (p < last && *p) {
                p++;
            }

            if (p < last && *data && (flags & ERR_TXT_STRING)) {
                *p++ = ':';
                p = ngx_cpystrn(p, (u_char *) data, last - p);
            }

        next:

            (void) ERR_get_error();
        }

        if (p < last) {
            *p++ = ')';
        }
    }

    ngx_log_error(level, log, err, "%*s", p - errstr, errstr);
}


ngx_int_t
ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ngx_array_t *certificates, ssize_t builtin_session_cache,
    ngx_shm_zone_t *shm_zone, time_t timeout)
{
    long  cache_mode;

    SSL_CTX_set_timeout(ssl->ctx, (long) timeout);

    if (ngx_ssl_session_id_context(ssl, sess_ctx, certificates) != NGX_OK) {
        return NGX_ERROR;
    }

    if (builtin_session_cache == NGX_SSL_NO_SCACHE) {
        SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);
        return NGX_OK;
    }

    if (builtin_session_cache == NGX_SSL_NONE_SCACHE) {

        /*
         * If the server explicitly says that it does not support
         * session reuse (see SSL_SESS_CACHE_OFF above), then
         * Outlook Express fails to upload a sent email to
         * the Sent Items folder on the IMAP server via a separate IMAP
         * connection in the background.  Therefore we have a special
         * mode (SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_STORE)
         * where the server pretends that it supports session reuse,
         * but it does not actually store any session.
         */

        SSL_CTX_set_session_cache_mode(ssl->ctx,
                                       SSL_SESS_CACHE_SERVER
                                       |SSL_SESS_CACHE_NO_AUTO_CLEAR
                                       |SSL_SESS_CACHE_NO_INTERNAL_STORE);

        SSL_CTX_sess_set_cache_size(ssl->ctx, 1);

        return NGX_OK;
    }

    cache_mode = SSL_SESS_CACHE_SERVER;

    if (shm_zone && builtin_session_cache == NGX_SSL_NO_BUILTIN_SCACHE) {
        cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx, cache_mode);

    if (builtin_session_cache != NGX_SSL_NO_BUILTIN_SCACHE) {

        if (builtin_session_cache != NGX_SSL_DFLT_BUILTIN_SCACHE) {
            SSL_CTX_sess_set_cache_size(ssl->ctx, builtin_session_cache);
        }
    }

    if (shm_zone) {
        SSL_CTX_sess_set_new_cb(ssl->ctx, ngx_ssl_new_session);
        SSL_CTX_sess_set_get_cb(ssl->ctx, ngx_ssl_get_cached_session);
        SSL_CTX_sess_set_remove_cb(ssl->ctx, ngx_ssl_remove_session);

        if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_session_cache_index, shm_zone)
            == 0)
        {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_set_ex_data() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_session_id_context(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ngx_array_t *certificates)
{
    int                   n, i;
    X509                 *cert;
    X509_NAME            *name;
    ngx_str_t            *certs;
    ngx_uint_t            k;
    EVP_MD_CTX           *md;
    unsigned int          len;
    STACK_OF(X509_NAME)  *list;
    u_char                buf[EVP_MAX_MD_SIZE];

    /*
     * Session ID context is set based on the string provided,
     * the server certificates, and the client CA list.
     */

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (EVP_DigestUpdate(md, sess_ctx->data, sess_ctx->len) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestUpdate() failed");
        goto failed;
    }

    for (k = 0; k < ssl->certs.nelts; k++) {
        cert = ((X509 **) ssl->certs.elts)[k];

        if (X509_digest(cert, EVP_sha1(), buf, &len) == 0) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "X509_digest() failed");
            goto failed;
        }

        if (EVP_DigestUpdate(md, buf, len) == 0) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "EVP_DigestUpdate() failed");
            goto failed;
        }
    }

    if (ssl->certs.nelts == 0 && certificates != NULL) {
        /*
         * If certificates are loaded dynamically, we use certificate
         * names as specified in the configuration (with variables).
         */

        certs = certificates->elts;
        for (k = 0; k < certificates->nelts; k++) {

            if (EVP_DigestUpdate(md, certs[k].data, certs[k].len) == 0) {
                ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                              "EVP_DigestUpdate() failed");
                goto failed;
            }
        }
    }

    list = SSL_CTX_get_client_CA_list(ssl->ctx);

    if (list != NULL) {
        n = sk_X509_NAME_num(list);

        for (i = 0; i < n; i++) {
            name = sk_X509_NAME_value(list, i);

            if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
                ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                              "X509_NAME_digest() failed");
                goto failed;
            }

            if (EVP_DigestUpdate(md, buf, len) == 0) {
                ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                              "EVP_DigestUpdate() failed");
                goto failed;
            }
        }
    }

    if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    EVP_MD_CTX_destroy(md);

    if (SSL_CTX_set_session_id_context(ssl->ctx, buf, len) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_session_id_context() failed");
        return NGX_ERROR;
    }

    return NGX_OK;

failed:

    EVP_MD_CTX_destroy(md);

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                    len;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_session_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_session_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    ngx_rbtree_init(&cache->session_rbtree, &cache->sentinel,
                    ngx_ssl_session_rbtree_insert_value);

    ngx_queue_init(&cache->expire_queue);

    cache->ticket_keys[0].expire = 0;
    cache->ticket_keys[1].expire = 0;
    cache->ticket_keys[2].expire = 0;

    cache->fail_time = 0;

    len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    shpool->log_nomem = 0;

    return NGX_OK;
}


/*
 * The length of the session id is 16 bytes for SSLv2 sessions and
 * between 1 and 32 bytes for SSLv3 and TLS, typically 32 bytes.
 * Typical length of the external ASN1 representation of a session
 * is about 150 bytes plus SNI server name.
 *
 * On 32-bit platforms we allocate an rbtree node, a session id, and
 * an ASN1 representation in a single allocation, it typically takes
 * 256 bytes.
 *
 * On 64-bit platforms we allocate separately an rbtree node + session_id,
 * and an ASN1 representation, they take accordingly 128 and 256 bytes.
 *
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

static int
ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    int                       len;
    u_char                   *p, *session_id;
    size_t                    n;
    uint32_t                  hash;
    SSL_CTX                  *ssl_ctx;
    unsigned int              session_id_length;
    ngx_shm_zone_t           *shm_zone;
    ngx_connection_t         *c;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;

#ifdef TLS1_3_VERSION

    /*
     * OpenSSL tries to save TLSv1.3 sessions into session cache
     * even when using tickets for stateless session resumption,
     * "because some applications just want to know about the creation
     * of a session"; do not cache such sessions
     */

    if (SSL_version(ssl_conn) == TLS1_3_VERSION
        && (SSL_get_options(ssl_conn) & SSL_OP_NO_TICKET) == 0)
    {
        return 0;
    }

#endif

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */

    if (len > NGX_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    p = ngx_ssl_session_buffer;
    i2d_SSL_SESSION(sess, &p);

    session_id = (u_char *) SSL_SESSION_get_id(sess, &session_id_length);

    /* do not cache sessions with too long session id */

    if (session_id_length > 32) {
        return 0;
    }

    c = ngx_ssl_get_connection(ssl_conn);

    ssl_ctx = c->ssl->session_ctx;
    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* drop one or two expired sessions */
    ngx_ssl_expire_sessions(cache, shpool, 1);

#if (NGX_PTR_SIZE == 8)
    n = sizeof(ngx_ssl_sess_id_t);
#else
    n = offsetof(ngx_ssl_sess_id_t, session) + len;
#endif

    sess_id = ngx_slab_alloc_locked(shpool, n);

    if (sess_id == NULL) {

        /* drop the oldest non-expired session and try once more */

        ngx_ssl_expire_sessions(cache, shpool, 0);

        sess_id = ngx_slab_alloc_locked(shpool, n);

        if (sess_id == NULL) {
            goto failed;
        }
    }

#if (NGX_PTR_SIZE == 8)

    sess_id->session = ngx_slab_alloc_locked(shpool, len);

    if (sess_id->session == NULL) {

        /* drop the oldest non-expired session and try once more */

        ngx_ssl_expire_sessions(cache, shpool, 0);

        sess_id->session = ngx_slab_alloc_locked(shpool, len);

        if (sess_id->session == NULL) {
            goto failed;
        }
    }

#endif

    ngx_memcpy(sess_id->session, ngx_ssl_session_buffer, len);
    ngx_memcpy(sess_id->id, session_id, session_id_length);

    hash = ngx_crc32_short(session_id, session_id_length);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl new session: %08XD:%ud:%d",
                   hash, session_id_length, len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) session_id_length;
    sess_id->len = len;

    sess_id->expire = ngx_time() + SSL_CTX_get_timeout(ssl_ctx);

    ngx_queue_insert_head(&cache->expire_queue, &sess_id->queue);

    ngx_rbtree_insert(&cache->session_rbtree, &sess_id->node);

    ngx_shmtx_unlock(&shpool->mutex);

    return 0;

failed:

    if (sess_id) {
        ngx_slab_free_locked(shpool, sess_id);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    if (cache->fail_time != ngx_time()) {
        cache->fail_time = ngx_time();
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "could not allocate new session%s", shpool->log_ctx);
    }

    return 0;
}


static ngx_ssl_session_t *
ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy)
{
    size_t                    slen;
    uint32_t                  hash;
    ngx_int_t                 rc;
    const u_char             *p;
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_connection_t         *c;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_session_t        *sess;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;

    hash = ngx_crc32_short((u_char *) (uintptr_t) id, (size_t) len);
    *copy = 0;

    c = ngx_ssl_get_connection(ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl get session: %08XD:%d", hash, len);

    shm_zone = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                                   ngx_ssl_session_cache_index);

    cache = shm_zone->data;

    sess = NULL;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (ngx_ssl_sess_id_t *) node;

        rc = ngx_memn2cmp((u_char *) (uintptr_t) id, sess_id->id,
                          (size_t) len, (size_t) node->data);

        if (rc == 0) {

            if (sess_id->expire > ngx_time()) {
                slen = sess_id->len;

                ngx_memcpy(ngx_ssl_session_buffer, sess_id->session, slen);

                ngx_shmtx_unlock(&shpool->mutex);

                p = ngx_ssl_session_buffer;
                sess = d2i_SSL_SESSION(NULL, &p, slen);

                return sess;
            }

            ngx_queue_remove(&sess_id->queue);

            ngx_rbtree_delete(&cache->session_rbtree, node);

            ngx_explicit_memzero(sess_id->session, sess_id->len);

#if (NGX_PTR_SIZE == 8)
            ngx_slab_free_locked(shpool, sess_id->session);
#endif
            ngx_slab_free_locked(shpool, sess_id);

            sess = NULL;

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:

    ngx_shmtx_unlock(&shpool->mutex);

    return sess;
}


void
ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
    SSL_CTX_remove_session(ssl, sess);

    ngx_ssl_remove_session(ssl, sess);
}


static void
ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
    u_char                   *id;
    uint32_t                  hash;
    ngx_int_t                 rc;
    unsigned int              len;
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;

    shm_zone = SSL_CTX_get_ex_data(ssl, ngx_ssl_session_cache_index);

    if (shm_zone == NULL) {
        return;
    }

    cache = shm_zone->data;

    id = (u_char *) SSL_SESSION_get_id(sess, &len);

    hash = ngx_crc32_short(id, len);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "ssl remove session: %08XD:%ud", hash, len);

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (ngx_ssl_sess_id_t *) node;

        rc = ngx_memn2cmp(id, sess_id->id, len, (size_t) node->data);

        if (rc == 0) {

            ngx_queue_remove(&sess_id->queue);

            ngx_rbtree_delete(&cache->session_rbtree, node);

            ngx_explicit_memzero(sess_id->session, sess_id->len);

#if (NGX_PTR_SIZE == 8)
            ngx_slab_free_locked(shpool, sess_id->session);
#endif
            ngx_slab_free_locked(shpool, sess_id);

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:

    ngx_shmtx_unlock(&shpool->mutex);
}


static void
ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n)
{
    time_t              now;
    ngx_queue_t        *q;
    ngx_ssl_sess_id_t  *sess_id;

    now = ngx_time();

    while (n < 3) {

        if (ngx_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = ngx_queue_last(&cache->expire_queue);

        sess_id = ngx_queue_data(q, ngx_ssl_sess_id_t, queue);

        if (n++ != 0 && sess_id->expire > now) {
            return;
        }

        ngx_queue_remove(q);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                       "expire session: %08Xi", sess_id->node.key);

        ngx_rbtree_delete(&cache->session_rbtree, &sess_id->node);

        ngx_explicit_memzero(sess_id->session, sess_id->len);

#if (NGX_PTR_SIZE == 8)
        ngx_slab_free_locked(shpool, sess_id->session);
#endif
        ngx_slab_free_locked(shpool, sess_id);
    }
}


static void
ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_ssl_sess_id_t   *sess_id, *sess_id_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sess_id = (ngx_ssl_sess_id_t *) node;
            sess_id_temp = (ngx_ssl_sess_id_t *) temp;

            p = (ngx_memn2cmp(sess_id->id, sess_id_temp->id,
                              (size_t) node->data, (size_t) temp->data)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

ngx_int_t
ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
{
    u_char                 buf[80];
    size_t                 size;
    ssize_t                n;
    ngx_str_t             *path;
    ngx_file_t             file;
    ngx_uint_t             i;
    ngx_array_t           *keys;
    ngx_file_info_t        fi;
    ngx_pool_cleanup_t    *cln;
    ngx_ssl_ticket_key_t  *key;

    if (paths == NULL
        && SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_session_cache_index) == NULL)
    {
        return NGX_OK;
    }

    keys = ngx_array_create(cf->pool, paths ? paths->nelts : 3,
                            sizeof(ngx_ssl_ticket_key_t));
    if (keys == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_ticket_keys_cleanup;
    cln->data = keys;

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_ticket_keys_index, keys) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx, ngx_ssl_ticket_key_callback)
        == 0)
    {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "nginx was built with Session Tickets support, however, "
                      "now it is linked dynamically to an OpenSSL library "
                      "which has no tlsext support, therefore Session Tickets "
                      "are not available");
        return NGX_OK;
    }

    if (paths == NULL) {

        /* placeholder for keys in shared memory */

        key = ngx_array_push_n(keys, 3);
        key[0].shared = 1;
        key[0].expire = 0;
        key[1].shared = 1;
        key[1].expire = 0;
        key[2].shared = 1;
        key[2].expire = 0;

        return NGX_OK;
    }

    path = paths->elts;
    for (i = 0; i < paths->nelts; i++) {

        if (ngx_conf_full_name(cf->cycle, &path[i], 1) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memzero(&file, sizeof(ngx_file_t));
        file.name = path[i];
        file.log = cf->log;

        file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                                NGX_FILE_OPEN, 0);

        if (file.fd == NGX_INVALID_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_open_file_n " \"%V\" failed", &file.name);
            return NGX_ERROR;
        }

        if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_fd_info_n " \"%V\" failed", &file.name);
            goto failed;
        }

        size = ngx_file_size(&fi);

        if (size != 48 && size != 80) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" must be 48 or 80 bytes", &file.name);
            goto failed;
        }

        n = ngx_read_file(&file, buf, size, 0);

        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%V\" failed", &file.name);
            goto failed;
        }

        if ((size_t) n != size) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
                               ngx_read_file_n " \"%V\" returned only "
                               "%z bytes instead of %uz", &file.name, n, size);
            goto failed;
        }

        key = ngx_array_push(keys);
        if (key == NULL) {
            goto failed;
        }

        key->shared = 0;
        key->expire = 1;

        if (size == 48) {
            key->size = 48;
            ngx_memcpy(key->name, buf, 16);
            ngx_memcpy(key->aes_key, buf + 16, 16);
            ngx_memcpy(key->hmac_key, buf + 32, 16);

        } else {
            key->size = 80;
            ngx_memcpy(key->name, buf, 16);
            ngx_memcpy(key->hmac_key, buf + 16, 32);
            ngx_memcpy(key->aes_key, buf + 48, 32);
        }

        if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " \"%V\" failed", &file.name);
        }

        ngx_explicit_memzero(&buf, 80);
    }

    return NGX_OK;

failed:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &file.name);
    }

    ngx_explicit_memzero(&buf, 80);

    return NGX_ERROR;
}


static int
ngx_ssl_ticket_key_callback(ngx_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc)
{
    size_t                 size;
    SSL_CTX               *ssl_ctx;
    ngx_uint_t             i;
    ngx_array_t           *keys;
    ngx_connection_t      *c;
    ngx_ssl_ticket_key_t  *key;
    const EVP_MD          *digest;
    const EVP_CIPHER      *cipher;

    c = ngx_ssl_get_connection(ssl_conn);
    ssl_ctx = c->ssl->session_ctx;

    if (ngx_ssl_rotate_ticket_keys(ssl_ctx, c->log) != NGX_OK) {
        return -1;
    }

#ifdef OPENSSL_NO_SHA256
    digest = EVP_sha1();
#else
    digest = EVP_sha256();
#endif

    keys = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index);
    if (keys == NULL) {
        return -1;
    }

    key = keys->elts;

    if (enc == 1) {
        /* encrypt session ticket */

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ticket encrypt, key: \"%*xs\" (%s session)",
                       (size_t) 16, key[0].name,
                       SSL_session_reused(ssl_conn) ? "reused" : "new");

        if (key[0].size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "RAND_bytes() failed");
            return -1;
        }

        if (EVP_EncryptInit_ex(ectx, cipher, NULL, key[0].aes_key, iv) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "EVP_EncryptInit_ex() failed");
            return -1;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if (HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }
#else
        HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL);
#endif

        ngx_memcpy(name, key[0].name, 16);

        return 1;

    } else {
        /* decrypt session ticket */

        for (i = 0; i < keys->nelts; i++) {
            if (ngx_memcmp(name, key[i].name, 16) == 0) {
                goto found;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ticket decrypt, key: \"%*xs\" not found",
                       (size_t) 16, name);

        return 0;

    found:

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ticket decrypt, key: \"%*xs\"%s",
                       (size_t) 16, key[i].name, (i == 0) ? " (default)" : "");

        if (key[i].size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if (HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }
#else
        HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL);
#endif

        if (EVP_DecryptInit_ex(ectx, cipher, NULL, key[i].aes_key, iv) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "EVP_DecryptInit_ex() failed");
            return -1;
        }

        /* renew if TLSv1.3 */

#ifdef TLS1_3_VERSION
        if (SSL_version(ssl_conn) == TLS1_3_VERSION) {
            return 2;
        }
#endif

        /* renew if non-default key */

        if (i != 0 && key[i].expire) {
            return 2;
        }

        return 1;
    }
}


static ngx_int_t
ngx_ssl_rotate_ticket_keys(SSL_CTX *ssl_ctx, ngx_log_t *log)
{
    time_t                    now, expire;
    ngx_array_t              *keys;
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_ticket_key_t     *key;
    ngx_ssl_session_cache_t  *cache;
    u_char                    buf[80];

    keys = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index);
    if (keys == NULL) {
        return NGX_OK;
    }

    key = keys->elts;

    if (!key[0].shared) {
        return NGX_OK;
    }

    /*
     * if we don't need to update expiration of the current key
     * and the previous key is still needed, don't sync with shared
     * memory to save some work; in the worst case other worker process
     * will switch to the next key, but this process will still be able
     * to decrypt tickets encrypted with it
     */

    now = ngx_time();
    expire = now + SSL_CTX_get_timeout(ssl_ctx);

    if (key[0].expire >= expire && key[1].expire >= now) {
        return NGX_OK;
    }

    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    key = cache->ticket_keys;

    if (key[0].expire == 0) {

        /* initialize the current key */

        if (RAND_bytes(buf, 80) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, "RAND_bytes() failed");
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        key[0].shared = 1;
        key[0].expire = expire;
        key[0].size = 80;
        ngx_memcpy(key[0].name, buf, 16);
        ngx_memcpy(key[0].hmac_key, buf + 16, 32);
        ngx_memcpy(key[0].aes_key, buf + 48, 32);

        ngx_explicit_memzero(&buf, 80);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "ssl ticket key: \"%*xs\"",
                       (size_t) 16, key[0].name);

        /*
         * copy the current key to the next key, as initialization of
         * the previous key will replace the current key with the next
         * key
         */

        key[2] = key[0];
    }

    if (key[1].expire < now) {

        /*
         * if the previous key is no longer needed (or not initialized),
         * replace it with the current key, replace the current key with
         * the next key, and generate new next key
         */

        key[1] = key[0];
        key[0] = key[2];

        if (RAND_bytes(buf, 80) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, "RAND_bytes() failed");
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        key[2].shared = 1;
        key[2].expire = 0;
        key[2].size = 80;
        ngx_memcpy(key[2].name, buf, 16);
        ngx_memcpy(key[2].hmac_key, buf + 16, 32);
        ngx_memcpy(key[2].aes_key, buf + 48, 32);

        ngx_explicit_memzero(&buf, 80);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "ssl ticket key: \"%*xs\"",
                       (size_t) 16, key[2].name);
    }

    /*
     * update expiration of the current key: it is going to be needed
     * at least till the session being created expires
     */

    if (expire > key[0].expire) {
        key[0].expire = expire;
    }

    /* sync keys to the worker process memory */

    ngx_memcpy(keys->elts, cache->ticket_keys,
               2 * sizeof(ngx_ssl_ticket_key_t));

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static void
ngx_ssl_ticket_keys_cleanup(void *data)
{
    ngx_array_t  *keys = data;

    ngx_explicit_memzero(keys->elts,
                         keys->nelts * sizeof(ngx_ssl_ticket_key_t));
}

#else

ngx_int_t
ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
{
    if (paths) {
        ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                      "\"ssl_session_ticket_key\" ignored, not supported");
    }

    return NGX_OK;
}

#endif


void
ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t  *ssl = data;

    X509        *cert;
    ngx_uint_t   i;

    for (i = 0; i < ssl->certs.nelts; i++) {
        cert = ((X509 **) ssl->certs.elts)[i];
        X509_free(cert);
    }

    SSL_CTX_free(ssl->ctx);
}


ngx_int_t
ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name)
{
    X509   *cert;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_ERROR;
    }

#ifdef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT

    /* X509_check_host() is only available in OpenSSL 1.0.2+ */

    if (name->len == 0) {
        goto failed;
    }

    if (X509_check_host(cert, (char *) name->data, name->len, 0, NULL) != 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "X509_check_host(): no match");
        goto failed;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "X509_check_host(): match");

    goto found;

#else
    {
    int                      n, i;
    X509_NAME               *sname;
    ASN1_STRING             *str;
    X509_NAME_ENTRY         *entry;
    GENERAL_NAME            *altname;
    STACK_OF(GENERAL_NAME)  *altnames;

    /*
     * As per RFC6125 and RFC2818, we check subjectAltName extension,
     * and if it's not present - commonName in Subject is checked.
     */

    altnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

    if (altnames) {
        n = sk_GENERAL_NAME_num(altnames);

        for (i = 0; i < n; i++) {
            altname = sk_GENERAL_NAME_value(altnames, i);

            if (altname->type != GEN_DNS) {
                continue;
            }

            str = altname->d.dNSName;

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL subjectAltName: \"%*s\"",
                           ASN1_STRING_length(str), ASN1_STRING_data(str));

            if (ngx_ssl_check_name(name, str) == NGX_OK) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "SSL subjectAltName: match");
                GENERAL_NAMES_free(altnames);
                goto found;
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL subjectAltName: no match");

        GENERAL_NAMES_free(altnames);
        goto failed;
    }

    /*
     * If there is no subjectAltName extension, check commonName
     * in Subject.  While RFC2818 requires to only check "most specific"
     * CN, both Apache and OpenSSL check all CNs, and so do we.
     */

    sname = X509_get_subject_name(cert);

    if (sname == NULL) {
        goto failed;
    }

    i = -1;
    for ( ;; ) {
        i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);

        if (i < 0) {
            break;
        }

        entry = X509_NAME_get_entry(sname, i);
        str = X509_NAME_ENTRY_get_data(entry);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL commonName: \"%*s\"",
                       ASN1_STRING_length(str), ASN1_STRING_data(str));

        if (ngx_ssl_check_name(name, str) == NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL commonName: match");
            goto found;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL commonName: no match");
    }
#endif

failed:

    X509_free(cert);
    return NGX_ERROR;

found:

    X509_free(cert);
    return NGX_OK;
}


#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT

static ngx_int_t
ngx_ssl_check_name(ngx_str_t *name, ASN1_STRING *pattern)
{
    u_char  *s, *p, *end;
    size_t   slen, plen;

    s = name->data;
    slen = name->len;

    p = ASN1_STRING_data(pattern);
    plen = ASN1_STRING_length(pattern);

    if (slen == plen && ngx_strncasecmp(s, p, plen) == 0) {
        return NGX_OK;
    }

    if (plen > 2 && p[0] == '*' && p[1] == '.') {
        plen -= 1;
        p += 1;

        end = s + slen;
        s = ngx_strlchr(s, end, '.');

        if (s == NULL) {
            return NGX_ERROR;
        }

        slen = end - s;

        if (plen == slen && ngx_strncasecmp(s, p, plen) == 0) {
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

#endif


ngx_int_t
ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) SSL_get_version(c->ssl->connection);
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) SSL_get_cipher_name(c->ssl->connection);
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
#ifdef SSL_CTRL_GET_RAW_CIPHERLIST

    int                n, i, bytes;
    size_t             len;
    u_char            *ciphers, *p;
    const SSL_CIPHER  *cipher;

    bytes = SSL_get0_raw_cipherlist(c->ssl->connection, NULL);
    n = SSL_get0_raw_cipherlist(c->ssl->connection, &ciphers);

    if (n <= 0) {
        s->len = 0;
        return NGX_OK;
    }

    len = 0;
    n /= bytes;

    for (i = 0; i < n; i++) {
        cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);

        if (cipher) {
            len += ngx_strlen(SSL_CIPHER_get_name(cipher));

        } else {
            len += sizeof("0x") - 1 + bytes * (sizeof("00") - 1);
        }

        len += sizeof(":") - 1;
    }

    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    p = s->data;

    for (i = 0; i < n; i++) {
        cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);

        if (cipher) {
            p = ngx_sprintf(p, "%s", SSL_CIPHER_get_name(cipher));

        } else {
            p = ngx_sprintf(p, "0x");
            p = ngx_hex_dump(p, ciphers + i * bytes, bytes);
        }

        *p++ = ':';
    }

    p--;

    s->len = p - s->data;

#else

    u_char  buf[4096];

    if (SSL_get_shared_ciphers(c->ssl->connection, (char *) buf, 4096)
        == NULL)
    {
        s->len = 0;
        return NGX_OK;
    }

    s->len = ngx_strlen(buf);
    s->data = ngx_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, buf, s->len);

#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
#ifdef SSL_get_negotiated_group

    int          nid;
    const char  *name;

    nid = SSL_get_negotiated_group(c->ssl->connection);

    if (nid != NID_undef) {

        if ((nid & TLSEXT_nid_unknown) == 0) {
            s->len = ngx_strlen(OBJ_nid2sn(nid));
            s->data = (u_char *) OBJ_nid2sn(nid);
            return NGX_OK;
        }

        name = SSL_group_to_name(c->ssl->connection, nid);

        s->len = name ? ngx_strlen(name) : sizeof("0x0000") - 1;
        s->data = ngx_pnalloc(pool, s->len);
        if (s->data == NULL) {
            return NGX_ERROR;
        }

        if (name) {
            ngx_memcpy(s->data, name, s->len);

        } else {
            ngx_sprintf(s->data, "0x%04xd", nid & 0xffff);
        }

        return NGX_OK;
    }

#endif

    s->len = 0;
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
#ifdef SSL_CTRL_GET_CURVES

    int         *curves, n, i, nid;
    u_char      *p;
    size_t       len;
    const char  *name;

    n = SSL_get1_curves(c->ssl->connection, NULL);

    if (n <= 0) {
        s->len = 0;
        return NGX_OK;
    }

    curves = ngx_palloc(pool, n * sizeof(int));
    if (curves == NULL) {
        return NGX_ERROR;
    }

    n = SSL_get1_curves(c->ssl->connection, curves);
    len = 0;

    for (i = 0; i < n; i++) {
        nid = curves[i];

        if (nid & TLSEXT_nid_unknown) {
            name = SSL_group_to_name(c->ssl->connection, nid);

            len += name ? ngx_strlen(name) : sizeof("0x0000") - 1;

        } else {
            len += ngx_strlen(OBJ_nid2sn(nid));
        }

        len += sizeof(":") - 1;
    }

    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    p = s->data;

    for (i = 0; i < n; i++) {
        nid = curves[i];

        if (nid & TLSEXT_nid_unknown) {
            name = SSL_group_to_name(c->ssl->connection, nid);

            p = name ? ngx_cpymem(p, name, ngx_strlen(name))
                     : ngx_sprintf(p, "0x%04xd", nid & 0xffff);

        } else {
            p = ngx_sprintf(p, "%s", OBJ_nid2sn(nid));
        }

        *p++ = ':';
    }

    p--;

    s->len = p - s->data;

#else

    s->len = 0;

#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    u_char        *buf;
    SSL_SESSION   *sess;
    unsigned int   len;

    sess = SSL_get0_session(c->ssl->connection);
    if (sess == NULL) {
        s->len = 0;
        return NGX_OK;
    }

    buf = (u_char *) SSL_SESSION_get_id(sess, &len);

    s->len = 2 * len;
    s->data = ngx_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(s->data, buf, len);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    if (SSL_session_reused(c->ssl->connection)) {
        ngx_str_set(s, "r");

    } else {
        ngx_str_set(s, ".");
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->len = 0;

#ifdef SSL_ERROR_EARLY_DATA_REJECTED

    /* BoringSSL */

    if (SSL_in_early_data(c->ssl->connection)) {
        ngx_str_set(s, "1");
    }

#elif defined SSL_READ_EARLY_DATA_SUCCESS

    /* OpenSSL */

    if (!SSL_is_init_finished(c->ssl->connection)) {
        ngx_str_set(s, "1");
    }

#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    size_t       len;
    const char  *name;

    name = SSL_get_servername(c->ssl->connection, TLSEXT_NAMETYPE_host_name);

    if (name) {
        len = ngx_strlen(name);

        s->len = len;
        s->data = ngx_pnalloc(pool, len);
        if (s->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(s->data, name, len);

        return NGX_OK;
    }

#endif

    s->len = 0;
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    unsigned int          len;
    const unsigned char  *data;

    SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

    if (len > 0) {

        s->data = ngx_pnalloc(pool, len);
        if (s->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(s->data, data, len);
        s->len = len;

        return NGX_OK;
    }

#endif

    s->len = 0;
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    size_t   len;
    BIO     *bio;
    X509    *cert;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");
        goto failed;
    }

    len = BIO_pending(bio);
    s->len = len;

    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, len);

    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    u_char      *p;
    size_t       len;
    ngx_uint_t   i;
    ngx_str_t    cert;

    if (ngx_ssl_get_raw_certificate(c, pool, &cert) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return NGX_OK;
    }

    len = cert.len - 1;

    for (i = 0; i < cert.len - 1; i++) {
        if (cert.data[i] == LF) {
            len++;
        }
    }

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    p = s->data;

    for (i = 0; i < cert.len - 1; i++) {
        *p++ = cert.data[i];
        if (cert.data[i] == LF) {
            *p++ = '\t';
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s)
{
    ngx_str_t  cert;
    uintptr_t  n;

    if (ngx_ssl_get_raw_certificate(c, pool, &cert) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return NGX_OK;
    }

    n = ngx_escape_uri(NULL, cert.data, cert.len, NGX_ESCAPE_URI_COMPONENT);

    s->len = cert.len + n * 2;
    s->data = ngx_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_escape_uri(s->data, cert.data, cert.len, NGX_ESCAPE_URI_COMPONENT);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    BIO        *bio;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_print_ex() failed");
        goto failed;
    }

    s->len = BIO_pending(bio);
    s->data = ngx_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, s->len);

    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    BIO        *bio;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_print_ex() failed");
        goto failed;
    }

    s->len = BIO_pending(bio);
    s->data = ngx_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, s->len);

    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);
    if (p == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_oneline() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);
    if (p == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_oneline() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    size_t   len;
    X509    *cert;
    BIO     *bio;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));
    len = BIO_pending(bio);

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NGX_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    X509          *cert;
    unsigned int   len;
    u_char         buf[EVP_MAX_MD_SIZE];

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    if (!X509_digest(cert, EVP_sha1(), buf, &len)) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_digest() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

    s->len = 2 * len;
    s->data = ngx_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    ngx_hex_dump(s->data, buf, len);

    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    X509        *cert;
    long         rc;
    const char  *str;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        ngx_str_set(s, "NONE");
        return NGX_OK;
    }

    X509_free(cert);

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc == X509_V_OK) {
        if (ngx_ssl_ocsp_get_status(c, &str) == NGX_OK) {
            ngx_str_set(s, "SUCCESS");
            return NGX_OK;
        }

    } else {
        str = X509_verify_cert_error_string(rc);
    }

    s->data = ngx_pnalloc(pool, sizeof("FAILED:") - 1 + ngx_strlen(str));
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    s->len = ngx_sprintf(s->data, "FAILED:%s", str) - s->data;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    BIO     *bio;
    X509    *cert;
    size_t   len;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, X509_get0_notBefore(cert));
#else
    ASN1_TIME_print(bio, X509_get_notBefore(cert));
#endif

    len = BIO_pending(bio);

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NGX_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    BIO     *bio;
    X509    *cert;
    size_t   len;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NGX_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, X509_get0_notAfter(cert));
#else
    ASN1_TIME_print(bio, X509_get_notAfter(cert));
#endif

    len = BIO_pending(bio);

    s->len = len;
    s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NGX_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    X509    *cert;
    time_t   now, end;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    end = ngx_ssl_parse_time(X509_get0_notAfter(cert), c->log);
#else
    end = ngx_ssl_parse_time(X509_get_notAfter(cert), c->log);
#endif

    if (end == (time_t) NGX_ERROR) {
        X509_free(cert);
        return NGX_OK;
    }

    now = ngx_time();

    if (end < now + 86400) {
        ngx_str_set(s, "0");
        X509_free(cert);
        return NGX_OK;
    }

    s->data = ngx_pnalloc(pool, NGX_TIME_T_LEN);
    if (s->data == NULL) {
        X509_free(cert);
        return NGX_ERROR;
    }

    s->len = ngx_sprintf(s->data, "%T", (end - now) / 86400) - s->data;

    X509_free(cert);

    return NGX_OK;
}


static time_t
ngx_ssl_parse_time(
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    const
#endif
    ASN1_TIME *asn1time, ngx_log_t *log)
{
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * OpenSSL doesn't provide a way to convert ASN1_TIME
     * into time_t.  To do this, we use ASN1_TIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, "BIO_new() failed");
        return NGX_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_TIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = ngx_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


static void *
ngx_openssl_create_conf(ngx_cycle_t *cycle)
{
    ngx_openssl_conf_t  *oscf;

    oscf = ngx_pcalloc(cycle->pool, sizeof(ngx_openssl_conf_t));
    if (oscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     oscf->engine = 0;
     */

    return oscf;
}


static char *
ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#ifndef OPENSSL_NO_ENGINE

    ngx_openssl_conf_t *oscf = conf;

    ENGINE     *engine;
    ngx_str_t  *value;

    if (oscf->engine) {
        return "is duplicate";
    }

    oscf->engine = 1;

    value = cf->args->elts;

    engine = ENGINE_by_id((char *) value[1].data);

    if (engine == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "ENGINE_by_id(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
                      &value[1]);

        ENGINE_free(engine);

        return NGX_CONF_ERROR;
    }

    ENGINE_free(engine);

    return NGX_CONF_OK;

#else

    return "is not supported";

#endif
}


static void
ngx_openssl_exit(ngx_cycle_t *cycle)
{
#if OPENSSL_VERSION_NUMBER < 0x10100003L

    EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif

#endif
}
