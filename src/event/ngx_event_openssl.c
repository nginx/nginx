
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_uint_t  engine;   /* unsigned  engine:1; */
} ngx_openssl_conf_t;


static int ngx_http_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
static void ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where,
    int ret);
static void ngx_ssl_handshake_handler(ngx_event_t *ev);
static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n);
static void ngx_ssl_write_handler(ngx_event_t *wev);
static void ngx_ssl_read_handler(ngx_event_t *rev);
static void ngx_ssl_shutdown_handler(ngx_event_t *ev);
static void ngx_ssl_connection_error(ngx_connection_t *c, int sslerr,
    ngx_err_t err, char *text);
static void ngx_ssl_clear_error(ngx_log_t *log);

ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);
static int ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn,
    ngx_ssl_session_t *sess);
static ngx_ssl_session_t *ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn,
    u_char *id, int len, int *copy);
static void ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
static void ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n);
static void ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

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
int  ngx_ssl_certificate_index;
int  ngx_ssl_stapling_index;


ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    OPENSSL_config(NULL);

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
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

    ngx_ssl_certificate_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (ngx_ssl_certificate_index == -1) {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_ssl_stapling_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                      NULL);
    if (ngx_ssl_stapling_index == -1) {
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

    /* client side options */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

    /* server side options */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

    /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

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
    if (!(protocols & NGX_SSL_TLSv1_1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    if (!(protocols & NGX_SSL_TLSv1_2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    }
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    SSL_CTX_set_info_callback(ssl->ctx, ngx_ssl_info_callback);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key)
{
    BIO     *bio;
    X509    *x509;
    u_long   n;

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * we can't use SSL_CTX_use_certificate_chain_file() as it doesn't
     * allow to access certificate later from SSL_CTX, so we reimplement
     * it here
     */

    bio = BIO_new_file((char *) cert->data, "r");
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", cert->data);
        return NGX_ERROR;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_X509_AUX(\"%s\") failed", cert->data);
        BIO_free(bio);
        return NGX_ERROR;
    }

    if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        BIO_free(bio);
        return NGX_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_certificate_index, x509)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    X509_free(x509);

    /* read rest of the chain */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "PEM_read_bio_X509(\"%s\") failed", cert->data);
            BIO_free(bio);
            return NGX_ERROR;
        }

        if (SSL_CTX_add_extra_chain_cert(ssl->ctx, x509) == 0) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_add_extra_chain_cert(\"%s\") failed",
                          cert->data);
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }
    }

    BIO_free(bio);

    if (ngx_conf_full_name(cf->cycle, key, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl->ctx, (char *) key->data,
                                    SSL_FILETYPE_PEM)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_PrivateKey_file(\"%s\") failed", key->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    STACK_OF(X509_NAME)  *list;

    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_http_ssl_verify_callback);

    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return NGX_ERROR;
    }

    list = SSL_load_client_CA_file((char *) cert->data);

    if (list == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_load_client_CA_file(\"%s\") failed", cert->data);
        return NGX_ERROR;
    }

    /*
     * before 0.9.7h and 0.9.8 SSL_load_client_CA_file()
     * always leaved an error in the error queue
     */

    ERR_clear_error();

    SSL_CTX_set_client_CA_list(ssl->ctx, list);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    X509_STORE   *store;
    X509_LOOKUP  *lookup;

    if (crl->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, crl, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NGX_ERROR;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

    if (lookup == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_add_lookup() failed");
        return NGX_ERROR;
    }

    if (X509_LOOKUP_load_file(lookup, (char *) crl->data, X509_FILETYPE_PEM)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_LOOKUP_load_file(\"%s\") failed", crl->data);
        return NGX_ERROR;
    }

    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    return NGX_OK;
}


static int
ngx_http_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
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

    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);
    subject = sname ? X509_NAME_oneline(sname, NULL, 0) : "(none)";

    iname = X509_get_issuer_name(cert);
    issuer = iname ? X509_NAME_oneline(iname, NULL, 0) : "(none)";

    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "verify:%d, error:%d, depth:%d, "
                   "subject:\"%s\",issuer: \"%s\"",
                   ok, err, depth, subject, issuer);

    if (sname) {
        OPENSSL_free(subject);
    }

    if (iname) {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}


static void
ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where, int ret)
{
    ngx_connection_t  *c;

    if (where & SSL_CB_HANDSHAKE_START) {
        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

        if (c->ssl->handshaked) {
            c->ssl->renegotiation = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
        }
    }
}


RSA *
ngx_ssl_rsa512_key_callback(SSL *ssl, int is_export, int key_length)
{
    static RSA  *key;

    if (key_length == 512) {
        if (key == NULL) {
            key = RSA_generate_key(512, RSA_F4, NULL, NULL);
        }
    }

    return key;
}


ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    DH   *dh;
    BIO  *bio;

    /*
     * -----BEGIN DH PARAMETERS-----
     * MIGHAoGBALu8LcrYRnSQfEP89YDpz9vZWKP1aLQtSwju1OsPs1BMbAMCducQgAxc
     * y7qokiYUxb7spWWl/fHSh6K8BJvmd4Bg6RqSp1fjBI9osHb302zI8pul34HcLKcl
     * 7OZicMyaUDXYzs7vnqAnSmOrHlj6/UmI0PZdFGdX2gcd8EXP4WubAgEC
     * -----END DH PARAMETERS-----
     */

    static unsigned char dh1024_p[] = {
        0xBB, 0xBC, 0x2D, 0xCA, 0xD8, 0x46, 0x74, 0x90, 0x7C, 0x43, 0xFC, 0xF5,
        0x80, 0xE9, 0xCF, 0xDB, 0xD9, 0x58, 0xA3, 0xF5, 0x68, 0xB4, 0x2D, 0x4B,
        0x08, 0xEE, 0xD4, 0xEB, 0x0F, 0xB3, 0x50, 0x4C, 0x6C, 0x03, 0x02, 0x76,
        0xE7, 0x10, 0x80, 0x0C, 0x5C, 0xCB, 0xBA, 0xA8, 0x92, 0x26, 0x14, 0xC5,
        0xBE, 0xEC, 0xA5, 0x65, 0xA5, 0xFD, 0xF1, 0xD2, 0x87, 0xA2, 0xBC, 0x04,
        0x9B, 0xE6, 0x77, 0x80, 0x60, 0xE9, 0x1A, 0x92, 0xA7, 0x57, 0xE3, 0x04,
        0x8F, 0x68, 0xB0, 0x76, 0xF7, 0xD3, 0x6C, 0xC8, 0xF2, 0x9B, 0xA5, 0xDF,
        0x81, 0xDC, 0x2C, 0xA7, 0x25, 0xEC, 0xE6, 0x62, 0x70, 0xCC, 0x9A, 0x50,
        0x35, 0xD8, 0xCE, 0xCE, 0xEF, 0x9E, 0xA0, 0x27, 0x4A, 0x63, 0xAB, 0x1E,
        0x58, 0xFA, 0xFD, 0x49, 0x88, 0xD0, 0xF6, 0x5D, 0x14, 0x67, 0x57, 0xDA,
        0x07, 0x1D, 0xF0, 0x45, 0xCF, 0xE1, 0x6B, 0x9B
    };

    static unsigned char dh1024_g[] = { 0x02 };


    if (file->len == 0) {

        dh = DH_new();
        if (dh == NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "DH_new() failed");
            return NGX_ERROR;
        }

        dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
        dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

        if (dh->p == NULL || dh->g == NULL) {
            ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "BN_bin2bn() failed");
            DH_free(dh);
            return NGX_ERROR;
        }

        SSL_CTX_set_tmp_dh(ssl->ctx, dh);

        DH_free(dh);

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

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (dh == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_DHparams(\"%s\") failed", file->data);
        BIO_free(bio);
        return NGX_ERROR;
    }

    SSL_CTX_set_tmp_dh(ssl->ctx, dh);

    DH_free(dh);
    BIO_free(bio);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
{
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
    int      nid;
    EC_KEY  *ecdh;

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

    nid = OBJ_sn2nid((const char *) name->data);
    if (nid == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "Unknown curve name \"%s\"", name->data);
        return NGX_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "Unable to create curve \"%s\"", name->data);
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
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_ssl_connection_t  *sc;

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->buffer = ((flags & NGX_SSL_BUFFER) != 0);

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
    }

    if (SSL_set_ex_data(sc->connection, ngx_ssl_connection_index, c) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        return NGX_ERROR;
    }

    c->ssl = sc;

    return NGX_OK;
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
        {
        char         buf[129], *s, *d;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        const
#endif
        SSL_CIPHER  *cipher;

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

        c->ssl->handshaked = 1;

        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;

        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
        if (c->ssl->connection->s3) {
            c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }

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

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

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
        ngx_log_error(NGX_LOG_INFO, c->log, err,
                      "peer closed connection in SSL handshake");

        return NGX_ERROR;
    }

    c->read->error = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    return NGX_ERROR;
}


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
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    u_char     *last;
    ssize_t     n, bytes;
    ngx_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {

        n = ngx_ssl_recv(c, last, b->end - last);

        if (n > 0) {
            last += n;
            bytes += n;

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

    if (c->ssl->last == NGX_ERROR) {
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
                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->error = 1;

            /* fall through */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }
}


static ngx_int_t
ngx_ssl_handle_recv(ngx_connection_t *c, int n)
{
    int        sslerr;
    ngx_err_t  err;

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
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

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
    int          n;
    ngx_uint_t   flush;
    ssize_t      send, size;
    ngx_buf_t   *buf;

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
            c->sent += n;

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
        buf = ngx_create_temp_buf(c->pool, NGX_SSL_BUFSIZE);
        if (buf == NULL) {
            return NGX_CHAIN_ERROR;
        }

        c->ssl->buf = buf;
    }

    if (buf->start == NULL) {
        buf->start = ngx_palloc(c->pool, NGX_SSL_BUFSIZE);
        if (buf->start == NULL) {
            return NGX_CHAIN_ERROR;
        }

        buf->pos = buf->start;
        buf->last = buf->start;
        buf->end = buf->start + NGX_SSL_BUFSIZE;
    }

    send = 0;
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

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %d", size);

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

        n = ngx_ssl_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        buf->pos += n;
        c->sent += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send == limit) {
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

    ngx_ssl_clear_error(c->log);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %d", size);

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

        return n;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

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


static void
ngx_ssl_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

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
    int        n, sslerr, mode;
    ngx_err_t  err;

    if (c->timedout) {
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

    n = SSL_shutdown(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

    sslerr = 0;

    /* SSL_shutdown() never returns -1, on error it returns 0 */

    if (n != 1 && ERR_peek_error()) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);
    }

    if (n == 1 || sslerr == 0 || sslerr == SSL_ERROR_ZERO_RETURN) {
        SSL_free(c->ssl->connection);
        c->ssl = NULL;

        return NGX_OK;
    }

    if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
        c->read->handler = ngx_ssl_shutdown_handler;
        c->write->handler = ngx_ssl_shutdown_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (sslerr == SSL_ERROR_WANT_READ) {
            ngx_add_timer(c->read, 30000);
        }

        return NGX_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");

    SSL_free(c->ssl->connection);
    c->ssl = NULL;

    return NGX_ERROR;
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


static void
ngx_ssl_connection_error(ngx_connection_t *c, int sslerr, ngx_err_t err,
    char *text)
{
    int         n;
    ngx_uint_t  level;

    level = NGX_LOG_CRIT;

    if (sslerr == SSL_ERROR_SYSCALL) {

        if (err == NGX_ECONNRESET
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

        n = ERR_GET_REASON(ERR_peek_error());

            /* handshake failures */
        if (n == SSL_R_BAD_CHANGE_CIPHER_SPEC                        /*  103 */
            || n == SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  /*  129 */
            || n == SSL_R_DIGEST_CHECK_FAILED                        /*  149 */
            || n == SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              /*  151 */
            || n == SSL_R_EXCESSIVE_MESSAGE_SIZE                     /*  152 */
            || n == SSL_R_LENGTH_MISMATCH                            /*  159 */
            || n == SSL_R_NO_CIPHERS_PASSED                          /*  182 */
            || n == SSL_R_NO_CIPHERS_SPECIFIED                       /*  183 */
            || n == SSL_R_NO_COMPRESSION_SPECIFIED                   /*  187 */
            || n == SSL_R_NO_SHARED_CIPHER                           /*  193 */
            || n == SSL_R_RECORD_LENGTH_MISMATCH                     /*  213 */
#ifdef SSL_R_PARSE_TLSEXT
            || n == SSL_R_PARSE_TLSEXT                               /*  227 */
#endif
            || n == SSL_R_UNEXPECTED_MESSAGE                         /*  244 */
            || n == SSL_R_UNEXPECTED_RECORD                          /*  245 */
            || n == SSL_R_UNKNOWN_ALERT_TYPE                         /*  246 */
            || n == SSL_R_UNKNOWN_PROTOCOL                           /*  252 */
            || n == SSL_R_WRONG_VERSION_NUMBER                       /*  267 */
            || n == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        /*  281 */
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
            || n == 1000 /* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
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
            || n == SSL_R_TLSV1_ALERT_NO_RENEGOTIATION)              /* 1100 */
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

    p = ngx_cpystrn(p, (u_char *) " (SSL:", last - p);

    for ( ;; ) {

        n = ERR_peek_error_line_data(NULL, NULL, &data, &flags);

        if (n == 0) {
            break;
        }

        if (p >= last) {
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

    ngx_log_error(level, log, err, "%s)", errstr);
}


ngx_int_t
ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout)
{
    long  cache_mode;

    if (builtin_session_cache == NGX_SSL_NO_SCACHE) {
        SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);
        return NGX_OK;
    }

    SSL_CTX_set_session_id_context(ssl->ctx, sess_ctx->data, sess_ctx->len);

    if (builtin_session_cache == NGX_SSL_NONE_SCACHE) {

        /*
         * If the server explicitly says that it does not support
         * session reuse (see SSL_SESS_CACHE_OFF above), then
         * Outlook Express fails to upload a sent email to
         * the Sent Items folder on the IMAP server via a separate IMAP
         * connection in the background. Therefore we have a special
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

    SSL_CTX_set_timeout(ssl->ctx, (long) timeout);

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

    if (shm_zone->shm.exists) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_session_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    ngx_rbtree_init(&cache->session_rbtree, &cache->sentinel,
                    ngx_ssl_session_rbtree_insert_value);

    ngx_queue_init(&cache->expire_queue);

    len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


/*
 * The length of the session id is 16 bytes for SSLv2 sessions and
 * between 1 and 32 bytes for SSLv3/TLSv1, typically 32 bytes.
 * It seems that the typical length of the external ASN1 representation
 * of a session is 118 or 119 bytes for SSLv3/TSLv1.
 *
 * Thus on 32-bit platforms we allocate separately an rbtree node,
 * a session id, and an ASN1 representation, they take accordingly
 * 64, 32, and 128 bytes.
 *
 * On 64-bit platforms we allocate separately an rbtree node + session_id,
 * and an ASN1 representation, they take accordingly 128 and 128 bytes.
 *
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

static int
ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    int                       len;
    u_char                   *p, *id, *cached_sess;
    uint32_t                  hash;
    SSL_CTX                  *ssl_ctx;
    ngx_shm_zone_t           *shm_zone;
    ngx_connection_t         *c;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;
    u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */

    if (len > (int) NGX_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    c = ngx_ssl_get_connection(ssl_conn);

    ssl_ctx = SSL_get_SSL_CTX(ssl_conn);
    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* drop one or two expired sessions */
    ngx_ssl_expire_sessions(cache, shpool, 1);

    cached_sess = ngx_slab_alloc_locked(shpool, len);

    if (cached_sess == NULL) {

        /* drop the oldest non-expired session and try once more */

        ngx_ssl_expire_sessions(cache, shpool, 0);

        cached_sess = ngx_slab_alloc_locked(shpool, len);

        if (cached_sess == NULL) {
            sess_id = NULL;
            goto failed;
        }
    }

    sess_id = ngx_slab_alloc_locked(shpool, sizeof(ngx_ssl_sess_id_t));
    if (sess_id == NULL) {
        goto failed;
    }

#if (NGX_PTR_SIZE == 8)

    id = sess_id->sess_id;

#else

    id = ngx_slab_alloc_locked(shpool, sess->session_id_length);
    if (id == NULL) {
        goto failed;
    }

#endif

    ngx_memcpy(cached_sess, buf, len);

    ngx_memcpy(id, sess->session_id, sess->session_id_length);

    hash = ngx_crc32_short(sess->session_id, sess->session_id_length);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl new session: %08XD:%d:%d",
                   hash, sess->session_id_length, len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) sess->session_id_length;
    sess_id->id = id;
    sess_id->len = len;
    sess_id->session = cached_sess;

    sess_id->expire = ngx_time() + SSL_CTX_get_timeout(ssl_ctx);

    ngx_queue_insert_head(&cache->expire_queue, &sess_id->queue);

    ngx_rbtree_insert(&cache->session_rbtree, &sess_id->node);

    ngx_shmtx_unlock(&shpool->mutex);

    return 0;

failed:

    if (cached_sess) {
        ngx_slab_free_locked(shpool, cached_sess);
    }

    if (sess_id) {
        ngx_slab_free_locked(shpool, sess_id);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "could not add new SSL session to the session cache");

    return 0;
}


static ngx_ssl_session_t *
ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn, u_char *id, int len,
    int *copy)
{
#if OPENSSL_VERSION_NUMBER >= 0x0090707fL
    const
#endif
    u_char                   *p;
    uint32_t                  hash;
    ngx_int_t                 rc;
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_session_t        *sess;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_cache_t  *cache;
    u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];
#if (NGX_DEBUG)
    ngx_connection_t         *c;
#endif

    hash = ngx_crc32_short(id, (size_t) len);
    *copy = 0;

#if (NGX_DEBUG)
    c = ngx_ssl_get_connection(ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl get session: %08XD:%d", hash, len);
#endif

    shm_zone = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl_conn),
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

        rc = ngx_memn2cmp(id, sess_id->id, (size_t) len, (size_t) node->data);

        if (rc == 0) {

            if (sess_id->expire > ngx_time()) {
                ngx_memcpy(buf, sess_id->session, sess_id->len);

                ngx_shmtx_unlock(&shpool->mutex);

                p = buf;
                sess = d2i_SSL_SESSION(NULL, &p, sess_id->len);

                return sess;
            }

            ngx_queue_remove(&sess_id->queue);

            ngx_rbtree_delete(&cache->session_rbtree, node);

            ngx_slab_free_locked(shpool, sess_id->session);
#if (NGX_PTR_SIZE == 4)
            ngx_slab_free_locked(shpool, sess_id->id);
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
    size_t                    len;
    u_char                   *id;
    uint32_t                  hash;
    ngx_int_t                 rc;
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

    id = sess->session_id;
    len = (size_t) sess->session_id_length;

    hash = ngx_crc32_short(id, len);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "ssl remove session: %08XD:%uz", hash, len);

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

            ngx_slab_free_locked(shpool, sess_id->session);
#if (NGX_PTR_SIZE == 4)
            ngx_slab_free_locked(shpool, sess_id->id);
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

        ngx_slab_free_locked(shpool, sess_id->session);
#if (NGX_PTR_SIZE == 4)
        ngx_slab_free_locked(shpool, sess_id->id);
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


void
ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t  *ssl = data;

    SSL_CTX_free(ssl->ctx);
}


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
ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    int           len;
    u_char       *p, *buf;
    SSL_SESSION  *sess;

    sess = SSL_get0_session(c->ssl->connection);

    len = i2d_SSL_SESSION(sess, NULL);

    buf = ngx_alloc(len, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    s->len = 2 * len;
    s->data = ngx_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        ngx_free(buf);
        return NGX_ERROR;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    ngx_hex_dump(s->data, buf, len);

    ngx_free(buf);

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
ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
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
ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
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
ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    X509  *cert;

    if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
        ngx_str_set(s, "FAILED");
        return NGX_OK;
    }

    cert = SSL_get_peer_certificate(c->ssl->connection);

    if (cert) {
        ngx_str_set(s, "SUCCESS");

    } else {
        ngx_str_set(s, "NONE");
    }

    X509_free(cert);

    return NGX_OK;
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
    ngx_openssl_conf_t *oscf = conf;

    ENGINE     *engine;
    ngx_str_t  *value;

    if (oscf->engine) {
        return "is duplicate";
    }

    oscf->engine = 1;

    value = cf->args->elts;

    engine = ENGINE_by_id((const char *) value[1].data);

    if (engine == NULL) {
        ngx_ssl_error(NGX_LOG_WARN, cf->log, 0,
                      "ENGINE_by_id(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
        ngx_ssl_error(NGX_LOG_WARN, cf->log, 0,
                      "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
                      &value[1]);

        ENGINE_free(engine);

        return NGX_CONF_ERROR;
    }

    ENGINE_free(engine);

    return NGX_CONF_OK;
}


static void
ngx_openssl_exit(ngx_cycle_t *cycle)
{
    EVP_cleanup();
    ENGINE_cleanup();
}
