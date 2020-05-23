
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)


typedef struct {
    ngx_str_t                    staple;
    ngx_msec_t                   timeout;

    ngx_resolver_t              *resolver;
    ngx_msec_t                   resolver_timeout;

    ngx_addr_t                  *addrs;
    ngx_uint_t                   naddrs;
    ngx_str_t                    host;
    ngx_str_t                    uri;
    in_port_t                    port;

    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;
    STACK_OF(X509)              *chain;

    u_char                      *name;

    time_t                       valid;
    time_t                       refresh;

    unsigned                     verify:1;
    unsigned                     loading:1;
} ngx_ssl_stapling_t;


typedef struct {
    ngx_addr_t                  *addrs;
    ngx_uint_t                   naddrs;

    ngx_str_t                    host;
    ngx_str_t                    uri;
    in_port_t                    port;
    ngx_uint_t                   depth;

    ngx_shm_zone_t              *shm_zone;

    ngx_resolver_t              *resolver;
    ngx_msec_t                   resolver_timeout;
} ngx_ssl_ocsp_conf_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  expire_queue;
} ngx_ssl_ocsp_cache_t;


typedef struct {
    ngx_str_node_t               node;
    ngx_queue_t                  queue;
    int                          status;
    time_t                       valid;
} ngx_ssl_ocsp_cache_node_t;


typedef struct ngx_ssl_ocsp_ctx_s  ngx_ssl_ocsp_ctx_t;


struct ngx_ssl_ocsp_s {
    STACK_OF(X509)              *certs;
    ngx_uint_t                   ncert;

    int                          cert_status;
    ngx_int_t                    status;

    ngx_ssl_ocsp_conf_t         *conf;
    ngx_ssl_ocsp_ctx_t          *ctx;
};


struct ngx_ssl_ocsp_ctx_s {
    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;
    STACK_OF(X509)              *chain;

    int                          status;
    time_t                       valid;

    u_char                      *name;

    ngx_uint_t                   naddrs;
    ngx_uint_t                   naddr;

    ngx_addr_t                  *addrs;
    ngx_str_t                    host;
    ngx_str_t                    uri;
    in_port_t                    port;

    ngx_resolver_t              *resolver;
    ngx_msec_t                   resolver_timeout;

    ngx_msec_t                   timeout;

    void                       (*handler)(ngx_ssl_ocsp_ctx_t *ctx);
    void                        *data;

    ngx_str_t                    key;
    ngx_buf_t                   *request;
    ngx_buf_t                   *response;
    ngx_peer_connection_t        peer;

    ngx_shm_zone_t              *shm_zone;

    ngx_int_t                  (*process)(ngx_ssl_ocsp_ctx_t *ctx);

    ngx_uint_t                   state;

    ngx_uint_t                   code;
    ngx_uint_t                   count;
    ngx_uint_t                   flags;
    ngx_uint_t                   done;

    u_char                      *header_name_start;
    u_char                      *header_name_end;
    u_char                      *header_start;
    u_char                      *header_end;

    ngx_pool_t                  *pool;
    ngx_log_t                   *log;
};


static ngx_int_t ngx_ssl_stapling_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    X509 *cert, ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
static ngx_int_t ngx_ssl_stapling_file(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_stapling_t *staple, ngx_str_t *file);
static ngx_int_t ngx_ssl_stapling_issuer(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_stapling_t *staple);
static ngx_int_t ngx_ssl_stapling_responder(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_stapling_t *staple, ngx_str_t *responder);

static int ngx_ssl_certificate_status_callback(ngx_ssl_conn_t *ssl_conn,
    void *data);
static void ngx_ssl_stapling_update(ngx_ssl_stapling_t *staple);
static void ngx_ssl_stapling_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx);

static time_t ngx_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time);

static void ngx_ssl_stapling_cleanup(void *data);

static void ngx_ssl_ocsp_validate_next(ngx_connection_t *c);
static void ngx_ssl_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_responder(ngx_connection_t *c,
    ngx_ssl_ocsp_ctx_t *ctx);

static ngx_ssl_ocsp_ctx_t *ngx_ssl_ocsp_start(ngx_log_t *log);
static void ngx_ssl_ocsp_done(ngx_ssl_ocsp_ctx_t *ctx);
static void ngx_ssl_ocsp_next(ngx_ssl_ocsp_ctx_t *ctx);
static void ngx_ssl_ocsp_request(ngx_ssl_ocsp_ctx_t *ctx);
static void ngx_ssl_ocsp_resolve_handler(ngx_resolver_ctx_t *resolve);
static void ngx_ssl_ocsp_connect(ngx_ssl_ocsp_ctx_t *ctx);
static void ngx_ssl_ocsp_write_handler(ngx_event_t *wev);
static void ngx_ssl_ocsp_read_handler(ngx_event_t *rev);
static void ngx_ssl_ocsp_dummy_handler(ngx_event_t *ev);

static ngx_int_t ngx_ssl_ocsp_create_request(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_process_status_line(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_parse_status_line(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_process_headers(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_parse_header_line(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_process_body(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_verify(ngx_ssl_ocsp_ctx_t *ctx);

static ngx_int_t ngx_ssl_ocsp_cache_lookup(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_cache_store(ngx_ssl_ocsp_ctx_t *ctx);
static ngx_int_t ngx_ssl_ocsp_create_key(ngx_ssl_ocsp_ctx_t *ctx);

static u_char *ngx_ssl_ocsp_log_error(ngx_log_t *log, u_char *buf, size_t len);


ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
    ngx_str_t *responder, ngx_uint_t verify)
{
    X509  *cert;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, ngx_ssl_next_certificate_index))
    {
        if (ngx_ssl_stapling_certificate(cf, ssl, cert, file, responder, verify)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    SSL_CTX_set_tlsext_status_cb(ssl->ctx, ngx_ssl_certificate_status_callback);

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_stapling_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, X509 *cert,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify)
{
    ngx_int_t            rc;
    ngx_pool_cleanup_t  *cln;
    ngx_ssl_stapling_t  *staple;

    staple = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_stapling_t));
    if (staple == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_stapling_cleanup;
    cln->data = staple;

    if (X509_set_ex_data(cert, ngx_ssl_stapling_index, staple) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        return NGX_ERROR;
    }

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
    /* OpenSSL 1.0.2+ */
    SSL_CTX_select_current_cert(ssl->ctx, cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
    /* OpenSSL 1.0.1+ */
    SSL_CTX_get_extra_chain_certs(ssl->ctx, &staple->chain);
#else
    staple->chain = ssl->ctx->extra_certs;
#endif

    staple->ssl_ctx = ssl->ctx;
    staple->timeout = 60000;
    staple->verify = verify;
    staple->cert = cert;
    staple->name = X509_get_ex_data(staple->cert,
                                    ngx_ssl_certificate_name_index);

    if (file->len) {
        /* use OCSP response from the file */

        if (ngx_ssl_stapling_file(cf, ssl, staple, file) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    rc = ngx_ssl_stapling_issuer(cf, ssl, staple);

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_ssl_stapling_responder(cf, ssl, staple, responder);

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_stapling_file(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_stapling_t *staple, ngx_str_t *file)
{
    BIO            *bio;
    int             len;
    u_char         *p, *buf;
    OCSP_RESPONSE  *response;

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "rb");
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return NGX_ERROR;
    }

    response = d2i_OCSP_RESPONSE_bio(bio, NULL);
    if (response == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "d2i_OCSP_RESPONSE_bio(\"%s\") failed", file->data);
        BIO_free(bio);
        return NGX_ERROR;
    }

    len = i2d_OCSP_RESPONSE(response, NULL);
    if (len <= 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        goto failed;
    }

    buf = ngx_alloc(len, ssl->log);
    if (buf == NULL) {
        goto failed;
    }

    p = buf;
    len = i2d_OCSP_RESPONSE(response, &p);
    if (len <= 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        ngx_free(buf);
        goto failed;
    }

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    staple->staple.data = buf;
    staple->staple.len = len;
    staple->valid = NGX_MAX_TIME_T_VALUE;

    return NGX_OK;

failed:

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    return NGX_ERROR;
}


static ngx_int_t
ngx_ssl_stapling_issuer(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_stapling_t *staple)
{
    int              i, n, rc;
    X509            *cert, *issuer;
    X509_STORE      *store;
    X509_STORE_CTX  *store_ctx;

    cert = staple->cert;

    n = sk_X509_num(staple->chain);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: %d extra certs", n);

    for (i = 0; i < n; i++) {
        issuer = sk_X509_value(staple->chain, i);
        if (X509_check_issued(issuer, cert) == X509_V_OK) {
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
            X509_up_ref(issuer);
#else
            CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
#endif

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
                           "SSL get issuer: found %p in extra certs", issuer);

            staple->issuer = issuer;

            return NGX_OK;
        }
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);
    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NGX_ERROR;
    }

    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_new() failed");
        return NGX_ERROR;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, NULL) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_init() failed");
        X509_STORE_CTX_free(store_ctx);
        return NGX_ERROR;
    }

    rc = X509_STORE_CTX_get1_issuer(&issuer, store_ctx, cert);

    if (rc == -1) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_get1_issuer() failed");
        X509_STORE_CTX_free(store_ctx);
        return NGX_ERROR;
    }

    if (rc == 0) {
        ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "issuer certificate not found for certificate \"%s\"",
                      staple->name);
        X509_STORE_CTX_free(store_ctx);
        return NGX_DECLINED;
    }

    X509_STORE_CTX_free(store_ctx);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: found %p in cert store", issuer);

    staple->issuer = issuer;

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_stapling_responder(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_stapling_t *staple, ngx_str_t *responder)
{
    char                      *s;
    ngx_str_t                  rsp;
    ngx_url_t                  u;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (responder->len == 0) {

        /* extract OCSP responder URL from certificate */

        aia = X509_get1_ocsp(staple->cert);
        if (aia == NULL) {
            ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            return NGX_DECLINED;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        s = sk_OPENSSL_STRING_value(aia, 0);
#else
        s = sk_value(aia, 0);
#endif
        if (s == NULL) {
            ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            X509_email_free(aia);
            return NGX_DECLINED;
        }

        responder = &rsp;

        responder->len = ngx_strlen(s);
        responder->data = ngx_palloc(cf->pool, responder->len);
        if (responder->data == NULL) {
            X509_email_free(aia);
            return NGX_ERROR;
        }

        ngx_memcpy(responder->data, s, responder->len);
        X509_email_free(aia);
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *responder;
    u.default_port = 80;
    u.uri_part = 1;

    if (u.url.len > 7
        && ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
    {
        u.url.len -= 7;
        u.url.data += 7;

    } else {
        ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "invalid URL prefix in OCSP responder \"%V\" "
                      "in the certificate \"%s\"",
                      &u.url, staple->name);
        return NGX_DECLINED;
    }

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "%s in OCSP responder \"%V\" "
                          "in the certificate \"%s\"",
                          u.err, &u.url, staple->name);
            return NGX_DECLINED;
        }

        return NGX_ERROR;
    }

    staple->addrs = u.addrs;
    staple->naddrs = u.naddrs;
    staple->host = u.host;
    staple->uri = u.uri;
    staple->port = u.port;

    if (staple->uri.len == 0) {
        ngx_str_set(&staple->uri, "/");
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    X509                *cert;
    ngx_ssl_stapling_t  *staple;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, ngx_ssl_next_certificate_index))
    {
        staple = X509_get_ex_data(cert, ngx_ssl_stapling_index);
        staple->resolver = resolver;
        staple->resolver_timeout = resolver_timeout;
    }

    return NGX_OK;
}


static int
ngx_ssl_certificate_status_callback(ngx_ssl_conn_t *ssl_conn, void *data)
{
    int                  rc;
    X509                *cert;
    u_char              *p;
    ngx_connection_t    *c;
    ngx_ssl_stapling_t  *staple;

    c = ngx_ssl_get_connection(ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL certificate status callback");

    rc = SSL_TLSEXT_ERR_NOACK;

    cert = SSL_get_certificate(ssl_conn);

    if (cert == NULL) {
        return rc;
    }

    staple = X509_get_ex_data(cert, ngx_ssl_stapling_index);

    if (staple == NULL) {
        return rc;
    }

    if (staple->staple.len
        && staple->valid >= ngx_time())
    {
        /* we have to copy ocsp response as OpenSSL will free it by itself */

        p = OPENSSL_malloc(staple->staple.len);
        if (p == NULL) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "OPENSSL_malloc() failed");
            return SSL_TLSEXT_ERR_NOACK;
        }

        ngx_memcpy(p, staple->staple.data, staple->staple.len);

        SSL_set_tlsext_status_ocsp_resp(ssl_conn, p, staple->staple.len);

        rc = SSL_TLSEXT_ERR_OK;
    }

    ngx_ssl_stapling_update(staple);

    return rc;
}


static void
ngx_ssl_stapling_update(ngx_ssl_stapling_t *staple)
{
    ngx_ssl_ocsp_ctx_t  *ctx;

    if (staple->host.len == 0
        || staple->loading || staple->refresh >= ngx_time())
    {
        return;
    }

    staple->loading = 1;

    ctx = ngx_ssl_ocsp_start(ngx_cycle->log);
    if (ctx == NULL) {
        return;
    }

    ctx->ssl_ctx = staple->ssl_ctx;
    ctx->cert = staple->cert;
    ctx->issuer = staple->issuer;
    ctx->chain = staple->chain;
    ctx->name = staple->name;
    ctx->flags = (staple->verify ? OCSP_TRUSTOTHER : OCSP_NOVERIFY);

    ctx->addrs = staple->addrs;
    ctx->naddrs = staple->naddrs;
    ctx->host = staple->host;
    ctx->uri = staple->uri;
    ctx->port = staple->port;
    ctx->timeout = staple->timeout;

    ctx->resolver = staple->resolver;
    ctx->resolver_timeout = staple->resolver_timeout;

    ctx->handler = ngx_ssl_stapling_ocsp_handler;
    ctx->data = staple;

    ngx_ssl_ocsp_request(ctx);

    return;
}


static void
ngx_ssl_stapling_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx)
{
    time_t               now;
    ngx_str_t            response;
    ngx_ssl_stapling_t  *staple;

    staple = ctx->data;
    now = ngx_time();

    if (ngx_ssl_ocsp_verify(ctx) != NGX_OK) {
        goto error;
    }

    if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "certificate status \"%s\" in the OCSP response",
                      OCSP_cert_status_str(ctx->status));
        goto error;
    }

    /* copy the response to memory not in ctx->pool */

    response.len = ctx->response->last - ctx->response->pos;
    response.data = ngx_alloc(response.len, ctx->log);

    if (response.data == NULL) {
        goto error;
    }

    ngx_memcpy(response.data, ctx->response->pos, response.len);

    if (staple->staple.data) {
        ngx_free(staple->staple.data);
    }

    staple->staple = response;
    staple->valid = ctx->valid;

    /*
     * refresh before the response expires,
     * but not earlier than in 5 minutes, and at least in an hour
     */

    staple->loading = 0;
    staple->refresh = ngx_max(ngx_min(ctx->valid - 300, now + 3600), now + 300);

    ngx_ssl_ocsp_done(ctx);
    return;

error:

    staple->loading = 0;
    staple->refresh = now + 300;

    ngx_ssl_ocsp_done(ctx);
}


static time_t
ngx_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time)
{
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * OpenSSL doesn't provide a way to convert ASN1_GENERALIZEDTIME
     * into time_t.  To do this, we use ASN1_GENERALIZEDTIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NGX_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_GENERALIZEDTIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = ngx_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


static void
ngx_ssl_stapling_cleanup(void *data)
{
    ngx_ssl_stapling_t  *staple = data;

    if (staple->issuer) {
        X509_free(staple->issuer);
    }

    if (staple->staple.data) {
        ngx_free(staple->staple.data);
    }
}


ngx_int_t
ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
{
    ngx_url_t             u;
    ngx_ssl_ocsp_conf_t  *ocf;

    ocf = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_ocsp_conf_t));
    if (ocf == NULL) {
        return NGX_ERROR;
    }

    ocf->depth = depth;
    ocf->shm_zone = shm_zone;

    if (responder->len) {
        ngx_memzero(&u, sizeof(ngx_url_t));

        u.url = *responder;
        u.default_port = 80;
        u.uri_part = 1;

        if (u.url.len > 7
            && ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
        {
            u.url.len -= 7;
            u.url.data += 7;

        } else {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "invalid URL prefix in OCSP responder \"%V\" "
                          "in \"ssl_ocsp_responder\"", &u.url);
            return NGX_ERROR;
        }

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "%s in OCSP responder \"%V\" "
                              "in \"ssl_ocsp_responder\"", u.err, &u.url);
            }

            return NGX_ERROR;
        }

        ocf->addrs = u.addrs;
        ocf->naddrs = u.naddrs;
        ocf->host = u.host;
        ocf->uri = u.uri;
        ocf->port = u.port;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_ocsp_index, ocf) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    ngx_ssl_ocsp_conf_t  *ocf;

    ocf = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_ocsp_index);
    ocf->resolver = resolver;
    ocf->resolver_timeout = resolver_timeout;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ocsp_validate(ngx_connection_t *c)
{
    X509                 *cert;
    SSL_CTX              *ssl_ctx;
    ngx_int_t             rc;
    X509_STORE           *store;
    X509_STORE_CTX       *store_ctx;
    STACK_OF(X509)       *chain;
    ngx_ssl_ocsp_t       *ocsp;
    ngx_ssl_ocsp_conf_t  *ocf;

    if (c->ssl->in_ocsp) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ssl_ctx = SSL_get_SSL_CTX(c->ssl->connection);

    ocf = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ocsp_index);
    if (ocf == NULL) {
        return NGX_OK;
    }

    if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
        return NGX_OK;
    }

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    ocsp = ngx_pcalloc(c->pool, sizeof(ngx_ssl_ocsp_t));
    if (ocsp == NULL) {
        return NGX_ERROR;
    }

    c->ssl->ocsp = ocsp;

    ocsp->status = NGX_AGAIN;
    ocsp->cert_status = V_OCSP_CERTSTATUS_GOOD;
    ocsp->conf = ocf;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)

    ocsp->certs = SSL_get0_verified_chain(c->ssl->connection);

    if (ocsp->certs) {
        ocsp->certs = X509_chain_up_ref(ocsp->certs);
        if (ocsp->certs == NULL) {
            return NGX_ERROR;
        }
    }

#endif

    if (ocsp->certs == NULL) {
        store = SSL_CTX_get_cert_store(ssl_ctx);
        if (store == NULL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "SSL_CTX_get_cert_store() failed");
            return NGX_ERROR;
        }

        store_ctx = X509_STORE_CTX_new();
        if (store_ctx == NULL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "X509_STORE_CTX_new() failed");
            return NGX_ERROR;
        }

        chain = SSL_get_peer_cert_chain(c->ssl->connection);

        if (X509_STORE_CTX_init(store_ctx, store, cert, chain) == 0) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "X509_STORE_CTX_init() failed");
            X509_STORE_CTX_free(store_ctx);
            return NGX_ERROR;
        }

        rc = X509_verify_cert(store_ctx);
        if (rc <= 0) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "X509_verify_cert() failed");
            X509_STORE_CTX_free(store_ctx);
            return NGX_ERROR;
        }

        ocsp->certs = X509_STORE_CTX_get1_chain(store_ctx);
        if (ocsp->certs == NULL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "X509_STORE_CTX_get1_chain() failed");
            X509_STORE_CTX_free(store_ctx);
            return NGX_ERROR;
        }

        X509_STORE_CTX_free(store_ctx);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl ocsp validate, certs:%d", sk_X509_num(ocsp->certs));

    ngx_ssl_ocsp_validate_next(c);

    if (ocsp->status == NGX_AGAIN) {
        c->ssl->in_ocsp = 1;
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_ssl_ocsp_validate_next(ngx_connection_t *c)
{
    ngx_int_t             rc;
    ngx_uint_t            n;
    ngx_ssl_ocsp_t       *ocsp;
    ngx_ssl_ocsp_ctx_t   *ctx;
    ngx_ssl_ocsp_conf_t  *ocf;

    ocsp = c->ssl->ocsp;
    ocf = ocsp->conf;

    n = sk_X509_num(ocsp->certs);

    for ( ;; ) {

        if (ocsp->ncert == n - 1 || (ocf->depth == 2 && ocsp->ncert == 1)) {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "ssl ocsp validated, certs:%ui", ocsp->ncert);
            goto done;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ocsp validate cert:%ui", ocsp->ncert);

        ctx = ngx_ssl_ocsp_start(c->log);
        if (ctx == NULL) {
            goto failed;
        }

        ocsp->ctx = ctx;

        ctx->ssl_ctx = SSL_get_SSL_CTX(c->ssl->connection);
        ctx->cert = sk_X509_value(ocsp->certs, ocsp->ncert);
        ctx->issuer = sk_X509_value(ocsp->certs, ocsp->ncert + 1);
        ctx->chain = ocsp->certs;

        ctx->resolver = ocf->resolver;
        ctx->resolver_timeout = ocf->resolver_timeout;

        ctx->handler = ngx_ssl_ocsp_handler;
        ctx->data = c;

        ctx->shm_zone = ocf->shm_zone;

        ctx->addrs = ocf->addrs;
        ctx->naddrs = ocf->naddrs;
        ctx->host = ocf->host;
        ctx->uri = ocf->uri;
        ctx->port = ocf->port;

        if (ngx_ssl_ocsp_responder(c, ctx) != NGX_OK) {
            goto failed;
        }

        if (ctx->uri.len == 0) {
            ngx_str_set(&ctx->uri, "/");
        }

        ocsp->ncert++;

        rc = ngx_ssl_ocsp_cache_lookup(ctx);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_DECLINED) {
            break;
        }

        /* rc == NGX_OK */

        if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp cached status \"%s\"",
                           OCSP_cert_status_str(ctx->status));
            ocsp->cert_status = ctx->status;
            goto done;
        }

        ocsp->ctx = NULL;
        ngx_ssl_ocsp_done(ctx);
    }

    ngx_ssl_ocsp_request(ctx);
    return;

done:

    ocsp->status = NGX_OK;
    return;

failed:

    ocsp->status = NGX_ERROR;
}


static void
ngx_ssl_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_ssl_ocsp_t    *ocsp;
    ngx_connection_t  *c;

    c = ctx->data;
    ocsp = c->ssl->ocsp;
    ocsp->ctx = NULL;

    rc = ngx_ssl_ocsp_verify(ctx);
    if (rc != NGX_OK) {
        ocsp->status = rc;
        ngx_ssl_ocsp_done(ctx);
        goto done;
    }

    rc = ngx_ssl_ocsp_cache_store(ctx);
    if (rc != NGX_OK) {
        ocsp->status = rc;
        ngx_ssl_ocsp_done(ctx);
        goto done;
    }

    if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
        ocsp->cert_status = ctx->status;
        ocsp->status = NGX_OK;
        ngx_ssl_ocsp_done(ctx);
        goto done;
    }

    ngx_ssl_ocsp_done(ctx);

    ngx_ssl_ocsp_validate_next(c);

done:

    if (ocsp->status == NGX_AGAIN || !c->ssl->in_ocsp) {
        return;
    }

    c->ssl->handshaked = 1;

    c->ssl->handler(c);
}


static ngx_int_t
ngx_ssl_ocsp_responder(ngx_connection_t *c, ngx_ssl_ocsp_ctx_t *ctx)
{
    char                      *s;
    ngx_str_t                  responder;
    ngx_url_t                  u;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (ctx->host.len) {
        return NGX_OK;
    }

    /* extract OCSP responder URL from certificate */

    aia = X509_get1_ocsp(ctx->cert);
    if (aia == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "no OCSP responder URL in certificate");
        return NGX_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    s = sk_OPENSSL_STRING_value(aia, 0);
#else
    s = sk_value(aia, 0);
#endif
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "no OCSP responder URL in certificate");
        X509_email_free(aia);
        return NGX_ERROR;
    }

    responder.len = ngx_strlen(s);
    responder.data = ngx_palloc(ctx->pool, responder.len);
    if (responder.data == NULL) {
        X509_email_free(aia);
        return NGX_ERROR;
    }

    ngx_memcpy(responder.data, s, responder.len);
    X509_email_free(aia);

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = responder;
    u.default_port = 80;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (u.url.len > 7
        && ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
    {
        u.url.len -= 7;
        u.url.data += 7;

    } else {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "invalid URL prefix in OCSP responder \"%V\" "
                      "in certificate", &u.url);
        return NGX_ERROR;
    }

    if (ngx_parse_url(ctx->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "%s in OCSP responder \"%V\" in certificate",
                          u.err, &u.url);
        }

        return NGX_ERROR;
    }

    if (u.host.len == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "empty host in OCSP responder in certificate");
        return NGX_ERROR;
    }

    ctx->addrs = u.addrs;
    ctx->naddrs = u.naddrs;
    ctx->host = u.host;
    ctx->uri = u.uri;
    ctx->port = u.port;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s)
{
    ngx_ssl_ocsp_t  *ocsp;

    ocsp = c->ssl->ocsp;
    if (ocsp == NULL) {
        return NGX_OK;
    }

    if (ocsp->status == NGX_ERROR) {
        *s = "certificate status request failed";
        return NGX_DECLINED;
    }

    switch (ocsp->cert_status) {

    case V_OCSP_CERTSTATUS_GOOD:
        return NGX_OK;

    case V_OCSP_CERTSTATUS_REVOKED:
        *s = "certificate revoked";
        break;

    default: /* V_OCSP_CERTSTATUS_UNKNOWN */
        *s = "certificate status unknown";
    }

    return NGX_DECLINED;
}


void
ngx_ssl_ocsp_cleanup(ngx_connection_t *c)
{
    ngx_ssl_ocsp_t  *ocsp;

    ocsp = c->ssl->ocsp;
    if (ocsp == NULL) {
        return;
    }

    if (ocsp->ctx) {
        ngx_ssl_ocsp_done(ocsp->ctx);
        ocsp->ctx = NULL;
    }

    if (ocsp->certs) {
        sk_X509_pop_free(ocsp->certs, X509_free);
        ocsp->certs = NULL;
    }
}


static ngx_ssl_ocsp_ctx_t *
ngx_ssl_ocsp_start(ngx_log_t *log)
{
    ngx_pool_t          *pool;
    ngx_ssl_ocsp_ctx_t  *ctx;

    pool = ngx_create_pool(2048, log);
    if (pool == NULL) {
        return NULL;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_ssl_ocsp_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ctx->pool = pool;

    *log = *ctx->pool->log;

    ctx->pool->log = log;
    ctx->log = log;

    log->handler = ngx_ssl_ocsp_log_error;
    log->data = ctx;
    log->action = "requesting certificate status";

    return ctx;
}


static void
ngx_ssl_ocsp_done(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp done");

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
    }

    ngx_destroy_pool(ctx->pool);
}


static void
ngx_ssl_ocsp_error(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp error");

    ctx->code = 0;
    ctx->handler(ctx);
}


static void
ngx_ssl_ocsp_next(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp next");

    if (++ctx->naddr >= ctx->naddrs) {
        ngx_ssl_ocsp_error(ctx);
        return;
    }

    ctx->request->pos = ctx->request->start;

    if (ctx->response) {
        ctx->response->last = ctx->response->pos;
    }

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }

    ctx->state = 0;
    ctx->count = 0;
    ctx->done = 0;

    ngx_ssl_ocsp_connect(ctx);
}


static void
ngx_ssl_ocsp_request(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_resolver_ctx_t  *resolve, temp;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request");

    if (ngx_ssl_ocsp_create_request(ctx) != NGX_OK) {
        ngx_ssl_ocsp_error(ctx);
        return;
    }

    if (ctx->resolver) {
        /* resolve OCSP responder hostname */

        temp.name = ctx->host;

        resolve = ngx_resolve_start(ctx->resolver, &temp);
        if (resolve == NULL) {
            ngx_ssl_ocsp_error(ctx);
            return;
        }

        if (resolve == NGX_NO_RESOLVER) {
            if (ctx->naddrs == 0) {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                              "no resolver defined to resolve %V", &ctx->host);

                ngx_ssl_ocsp_error(ctx);
                return;
            }

            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                          "no resolver defined to resolve %V", &ctx->host);
            goto connect;
        }

        resolve->name = ctx->host;
        resolve->handler = ngx_ssl_ocsp_resolve_handler;
        resolve->data = ctx;
        resolve->timeout = ctx->resolver_timeout;

        if (ngx_resolve_name(resolve) != NGX_OK) {
            ngx_ssl_ocsp_error(ctx);
            return;
        }

        return;
    }

connect:

    ngx_ssl_ocsp_connect(ctx);
}


static void
ngx_ssl_ocsp_resolve_handler(ngx_resolver_ctx_t *resolve)
{
    ngx_ssl_ocsp_ctx_t *ctx = resolve->data;

    u_char           *p;
    size_t            len;
    socklen_t         socklen;
    ngx_uint_t        i;
    struct sockaddr  *sockaddr;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp resolve handler");

    if (resolve->state) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &resolve->name, resolve->state,
                      ngx_resolver_strerror(resolve->state));
        goto failed;
    }

#if (NGX_DEBUG)
    {
    u_char     text[NGX_SOCKADDR_STRLEN];
    ngx_str_t  addr;

    addr.data = text;

    for (i = 0; i < resolve->naddrs; i++) {
        addr.len = ngx_sock_ntop(resolve->addrs[i].sockaddr,
                                 resolve->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "name was resolved to %V", &addr);

    }
    }
#endif

    ctx->naddrs = resolve->naddrs;
    ctx->addrs = ngx_pcalloc(ctx->pool, ctx->naddrs * sizeof(ngx_addr_t));

    if (ctx->addrs == NULL) {
        goto failed;
    }

    for (i = 0; i < resolve->naddrs; i++) {

        socklen = resolve->addrs[i].socklen;

        sockaddr = ngx_palloc(ctx->pool, socklen);
        if (sockaddr == NULL) {
            goto failed;
        }

        ngx_memcpy(sockaddr, resolve->addrs[i].sockaddr, socklen);
        ngx_inet_set_port(sockaddr, ctx->port);

        ctx->addrs[i].sockaddr = sockaddr;
        ctx->addrs[i].socklen = socklen;

        p = ngx_pnalloc(ctx->pool, NGX_SOCKADDR_STRLEN);
        if (p == NULL) {
            goto failed;
        }

        len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);

        ctx->addrs[i].name.len = len;
        ctx->addrs[i].name.data = p;
    }

    ngx_resolve_name_done(resolve);

    ngx_ssl_ocsp_connect(ctx);
    return;

failed:

    ngx_resolve_name_done(resolve);
    ngx_ssl_ocsp_error(ctx);
}


static void
ngx_ssl_ocsp_connect(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_int_t    rc;
    ngx_addr_t  *addr;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect %ui/%ui", ctx->naddr, ctx->naddrs);

    addr = &ctx->addrs[ctx->naddr];

    ctx->peer.sockaddr = addr->sockaddr;
    ctx->peer.socklen = addr->socklen;
    ctx->peer.name = &addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect peer done");

    if (rc == NGX_ERROR) {
        ngx_ssl_ocsp_error(ctx);
        return;
    }

    if (rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_ssl_ocsp_next(ctx);
        return;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = ctx->pool;

    ctx->peer.connection->read->handler = ngx_ssl_ocsp_read_handler;
    ctx->peer.connection->write->handler = ngx_ssl_ocsp_write_handler;

    ctx->process = ngx_ssl_ocsp_process_status_line;

    if (ctx->timeout) {
        ngx_add_timer(ctx->peer.connection->read, ctx->timeout);
        ngx_add_timer(ctx->peer.connection->write, ctx->timeout);
    }

    if (rc == NGX_OK) {
        ngx_ssl_ocsp_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
ngx_ssl_ocsp_write_handler(ngx_event_t *wev)
{
    ssize_t              n, size;
    ngx_connection_t    *c;
    ngx_ssl_ocsp_ctx_t  *ctx;

    c = wev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, wev->log, 0,
                   "ssl ocsp write handler");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "OCSP responder timed out");
        ngx_ssl_ocsp_next(ctx);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = ngx_send(c, ctx->request->pos, size);

    if (n == NGX_ERROR) {
        ngx_ssl_ocsp_next(ctx);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = ngx_ssl_ocsp_dummy_handler;

            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_ssl_ocsp_error(ctx);
            }

            return;
        }
    }

    if (!wev->timer_set && ctx->timeout) {
        ngx_add_timer(wev, ctx->timeout);
    }
}


static void
ngx_ssl_ocsp_read_handler(ngx_event_t *rev)
{
    ssize_t              n, size;
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_ssl_ocsp_ctx_t  *ctx;

    c = rev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0,
                   "ssl ocsp read handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "OCSP responder timed out");
        ngx_ssl_ocsp_next(ctx);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, 16384);
        if (ctx->response == NULL) {
            ngx_ssl_ocsp_error(ctx);
            return;
        }
    }

    for ( ;; ) {

        size = ctx->response->end - ctx->response->last;

        n = ngx_recv(c, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;

            rc = ctx->process(ctx);

            if (rc == NGX_ERROR) {
                ngx_ssl_ocsp_next(ctx);
                return;
            }

            continue;
        }

        if (n == NGX_AGAIN) {

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_ssl_ocsp_error(ctx);
            }

            return;
        }

        break;
    }

    ctx->done = 1;

    rc = ctx->process(ctx);

    if (rc == NGX_DONE) {
        /* ctx->handler() was called */
        return;
    }

    ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                  "OCSP responder prematurely closed connection");

    ngx_ssl_ocsp_next(ctx);
}


static void
ngx_ssl_ocsp_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "ssl ocsp dummy handler");
}


static ngx_int_t
ngx_ssl_ocsp_create_request(ngx_ssl_ocsp_ctx_t *ctx)
{
    int            len;
    u_char        *p;
    uintptr_t      escape;
    ngx_str_t      binary, base64;
    ngx_buf_t     *b;
    OCSP_CERTID   *id;
    OCSP_REQUEST  *ocsp;

    ocsp = OCSP_REQUEST_new();
    if (ocsp == NULL) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "OCSP_REQUEST_new() failed");
        return NGX_ERROR;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto failed;
    }

    if (OCSP_request_add0_id(ocsp, id) == NULL) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "OCSP_request_add0_id() failed");
        OCSP_CERTID_free(id);
        goto failed;
    }

    len = i2d_OCSP_REQUEST(ocsp, NULL);
    if (len <= 0) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    binary.len = len;
    binary.data = ngx_palloc(ctx->pool, len);
    if (binary.data == NULL) {
        goto failed;
    }

    p = binary.data;
    len = i2d_OCSP_REQUEST(ocsp, &p);
    if (len <= 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    base64.len = ngx_base64_encoded_length(binary.len);
    base64.data = ngx_palloc(ctx->pool, base64.len);
    if (base64.data == NULL) {
        goto failed;
    }

    ngx_encode_base64(&base64, &binary);

    escape = ngx_escape_uri(NULL, base64.data, base64.len,
                            NGX_ESCAPE_URI_COMPONENT);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request length %z, escape %d",
                   base64.len, (int) escape);

    len = sizeof("GET ") - 1 + ctx->uri.len + sizeof("/") - 1
          + base64.len + 2 * escape + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ctx->host.len + sizeof(CRLF) - 1
          + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(ctx->pool, len);
    if (b == NULL) {
        goto failed;
    }

    p = b->last;

    p = ngx_cpymem(p, "GET ", sizeof("GET ") - 1);
    p = ngx_cpymem(p, ctx->uri.data, ctx->uri.len);

    if (ctx->uri.data[ctx->uri.len - 1] != '/') {
        *p++ = '/';
    }

    if (escape == 0) {
        p = ngx_cpymem(p, base64.data, base64.len);

    } else {
        p = (u_char *) ngx_escape_uri(p, base64.data, base64.len,
                                      NGX_ESCAPE_URI_COMPONENT);
    }

    p = ngx_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
    p = ngx_cpymem(p, "Host: ", sizeof("Host: ") - 1);
    p = ngx_cpymem(p, ctx->host.data, ctx->host.len);
    *p++ = CR; *p++ = LF;

    /* add "\r\n" at the header end */
    *p++ = CR; *p++ = LF;

    b->last = p;
    ctx->request = b;

    OCSP_REQUEST_free(ocsp);

    return NGX_OK;

failed:

    OCSP_REQUEST_free(ocsp);

    return NGX_ERROR;
}


static ngx_int_t
ngx_ssl_ocsp_process_status_line(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_int_t  rc;

    rc = ngx_ssl_ocsp_parse_status_line(ctx);

    if (rc == NGX_OK) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp status %ui \"%*s\"",
                       ctx->code,
                       ctx->header_end - ctx->header_start,
                       ctx->header_start);

        ctx->process = ngx_ssl_ocsp_process_headers;
        return ctx->process(ctx);
    }

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /* rc == NGX_ERROR */

    ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                  "OCSP responder sent invalid response");

    return NGX_ERROR;
}


static ngx_int_t
ngx_ssl_ocsp_parse_status_line(ngx_ssl_ocsp_ctx_t *ctx)
{
    u_char      ch;
    u_char     *p;
    ngx_buf_t  *b;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process status line");

    state = ctx->state;
    b = ctx->response;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            ctx->code = ctx->code * 10 + (ch - '0');

            if (++ctx->count == 3) {
                state = sw_space_after_status;
                ctx->header_start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                ctx->header_end = p - 1;
                goto done;
            default:
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_ocsp_process_headers(ngx_ssl_ocsp_ctx_t *ctx)
{
    size_t     len;
    ngx_int_t  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process headers");

    for ( ;; ) {
        rc = ngx_ssl_ocsp_parse_header_line(ctx);

        if (rc == NGX_OK) {

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp header \"%*s: %*s\"",
                           ctx->header_name_end - ctx->header_name_start,
                           ctx->header_name_start,
                           ctx->header_end - ctx->header_start,
                           ctx->header_start);

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Content-Type") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Content-Type",
                                   sizeof("Content-Type") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len != sizeof("application/ocsp-response") - 1
                    || ngx_strncasecmp(ctx->header_start,
                                       (u_char *) "application/ocsp-response",
                                       sizeof("application/ocsp-response") - 1)
                       != 0)
                {
                    ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                                  "OCSP responder sent invalid "
                                  "\"Content-Type\" header: \"%*s\"",
                                  ctx->header_end - ctx->header_start,
                                  ctx->header_start);
                    return NGX_ERROR;
                }

                continue;
            }

            /* TODO: honor Content-Length */

            continue;
        }

        if (rc == NGX_DONE) {
            break;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_ERROR */

        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "OCSP responder sent invalid response");

        return NGX_ERROR;
    }

    ctx->process = ngx_ssl_ocsp_process_body;
    return ctx->process(ctx);
}


static ngx_int_t
ngx_ssl_ocsp_parse_header_line(ngx_ssl_ocsp_ctx_t *ctx)
{
    u_char  c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "s:%d in:'%02Xd:%c'", state, ch, ch);
#endif

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NGX_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NGX_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
}


static ngx_int_t
ngx_ssl_ocsp_process_body(ngx_ssl_ocsp_ctx_t *ctx)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process body");

    if (ctx->done) {
        ctx->handler(ctx);
        return NGX_DONE;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_ssl_ocsp_verify(ngx_ssl_ocsp_ctx_t *ctx)
{
    int                    n;
    size_t                 len;
    X509_STORE            *store;
    const u_char          *p;
    OCSP_CERTID           *id;
    OCSP_RESPONSE         *ocsp;
    OCSP_BASICRESP        *basic;
    ASN1_GENERALIZEDTIME  *thisupdate, *nextupdate;

    ocsp = NULL;
    basic = NULL;
    id = NULL;

    if (ctx->code != 200) {
        goto error;
    }

    /* check the response */

    len = ctx->response->last - ctx->response->pos;
    p = ctx->response->pos;

    ocsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (ocsp == NULL) {
        ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
                      "d2i_OCSP_RESPONSE() failed");
        goto error;
    }

    n = OCSP_response_status(ocsp);

    if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "OCSP response not successful (%d: %s)",
                      n, OCSP_response_status_str(n));
        goto error;
    }

    basic = OCSP_response_get1_basic(ocsp);
    if (basic == NULL) {
        ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
                      "OCSP_response_get1_basic() failed");
        goto error;
    }

    store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        goto error;
    }

    if (OCSP_basic_verify(basic, ctx->chain, store, ctx->flags) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
                      "OCSP_basic_verify() failed");
        goto error;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto error;
    }

    if (OCSP_resp_find_status(basic, id, &ctx->status, NULL, NULL,
                              &thisupdate, &nextupdate)
        != 1)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "certificate status not found in the OCSP response");
        goto error;
    }

    if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
                      "OCSP_check_validity() failed");
        goto error;
    }

    if (nextupdate) {
        ctx->valid = ngx_ssl_stapling_time(nextupdate);
        if (ctx->valid == (time_t) NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "invalid nextUpdate time in certificate status");
            goto error;
        }

    } else {
        ctx->valid = NGX_MAX_TIME_T_VALUE;
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(ocsp);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp response, %s, %uz",
                   OCSP_cert_status_str(ctx->status), len);

    return NGX_OK;

error:

    if (id) {
        OCSP_CERTID_free(id);
    }

    if (basic) {
        OCSP_BASICRESP_free(basic);
    }

    if (ocsp) {
        OCSP_RESPONSE_free(ocsp);
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                 len;
    ngx_slab_pool_t       *shpool;
    ngx_ssl_ocsp_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_ocsp_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
                    ngx_str_rbtree_insert_value);

    ngx_queue_init(&cache->expire_queue);

    len = sizeof(" in OCSP cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in OCSP cache \"%V\"%Z",
                &shm_zone->shm.name);

    shpool->log_nomem = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_ocsp_cache_lookup(ngx_ssl_ocsp_ctx_t *ctx)
{
    uint32_t                    hash;
    ngx_shm_zone_t             *shm_zone;
    ngx_slab_pool_t            *shpool;
    ngx_ssl_ocsp_cache_t       *cache;
    ngx_ssl_ocsp_cache_node_t  *node;

    shm_zone = ctx->shm_zone;

    if (shm_zone == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_ssl_ocsp_create_key(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0, "ssl ocsp cache lookup");

    cache = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    hash = ngx_hash_key(ctx->key.data, ctx->key.len);

    ngx_shmtx_lock(&shpool->mutex);

    node = (ngx_ssl_ocsp_cache_node_t *)
               ngx_str_rbtree_lookup(&cache->rbtree, &ctx->key, hash);

    if (node) {
        if (node->valid > ngx_time()) {
            ctx->status = node->status;
            ngx_shmtx_unlock(&shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp cache hit, %s",
                           OCSP_cert_status_str(ctx->status));

            return NGX_OK;
        }

        ngx_queue_remove(&node->queue);
        ngx_rbtree_delete(&cache->rbtree, &node->node.node);
        ngx_slab_free_locked(shpool, node);

        ngx_shmtx_unlock(&shpool->mutex);

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp cache expired");

        return NGX_DECLINED;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0, "ssl ocsp cache miss");

    return NGX_DECLINED;
}


static ngx_int_t
ngx_ssl_ocsp_cache_store(ngx_ssl_ocsp_ctx_t *ctx)
{
    time_t                      now, valid;
    uint32_t                    hash;
    ngx_queue_t                *q;
    ngx_shm_zone_t             *shm_zone;
    ngx_slab_pool_t            *shpool;
    ngx_ssl_ocsp_cache_t       *cache;
    ngx_ssl_ocsp_cache_node_t  *node;

    shm_zone = ctx->shm_zone;

    if (shm_zone == NULL) {
        return NGX_OK;
    }

    valid = ctx->valid;

    now = ngx_time();

    if (valid < now) {
        return NGX_OK;
    }

    if (valid == NGX_MAX_TIME_T_VALUE) {
        valid = now + 3600;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp cache store, valid:%T", valid - now);

    cache = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    hash = ngx_hash_key(ctx->key.data, ctx->key.len);

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_slab_calloc_locked(shpool,
                             sizeof(ngx_ssl_ocsp_cache_node_t) + ctx->key.len);
    if (node == NULL) {

        if (!ngx_queue_empty(&cache->expire_queue)) {
            q = ngx_queue_last(&cache->expire_queue);
            node = ngx_queue_data(q, ngx_ssl_ocsp_cache_node_t, queue);

            ngx_rbtree_delete(&cache->rbtree, &node->node.node);
            ngx_queue_remove(q);
            ngx_slab_free_locked(shpool, node);

            node = ngx_slab_alloc_locked(shpool,
                             sizeof(ngx_ssl_ocsp_cache_node_t) + ctx->key.len);
        }

        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                          "could not allocate new entry%s", shpool->log_ctx);
            return NGX_ERROR;
        }
    }

    node->node.str.len = ctx->key.len;
    node->node.str.data = (u_char *) node + sizeof(ngx_ssl_ocsp_cache_node_t);
    ngx_memcpy(node->node.str.data, ctx->key.data, ctx->key.len);
    node->node.node.key = hash;
    node->status = ctx->status;
    node->valid = valid;

    ngx_rbtree_insert(&cache->rbtree, &node->node.node);
    ngx_queue_insert_head(&cache->expire_queue, &node->queue);

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_ocsp_create_key(ngx_ssl_ocsp_ctx_t *ctx)
{
    u_char        *p;
    X509_NAME     *name;
    ASN1_INTEGER  *serial;

    p = ngx_pnalloc(ctx->pool, 60);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ctx->key.data = p;
    ctx->key.len = 60;

    name = X509_get_subject_name(ctx->issuer);
    if (X509_NAME_digest(name, EVP_sha1(), p, NULL) == 0) {
        return NGX_ERROR;
    }

    p += 20;

    if (X509_pubkey_digest(ctx->issuer, EVP_sha1(), p, NULL) == 0) {
        return NGX_ERROR;
    }

    p += 20;

    serial = X509_get_serialNumber(ctx->cert);
    if (serial->length > 20) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(p, serial->data, serial->length);
    ngx_memzero(p, 20 - serial->length);

#if (NGX_DEBUG)
    {
        u_char  buf[120];

        ngx_hex_dump(buf, ctx->key.data, ctx->key.len);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp key %*s", sizeof(buf), buf);
    }
#endif

    return NGX_OK;
}


static u_char *
ngx_ssl_ocsp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_ssl_ocsp_ctx_t  *ctx;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    if (ctx) {
        p = ngx_snprintf(buf, len, ", responder: %V", &ctx->host);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->peer.name) {
        p = ngx_snprintf(buf, len, ", peer: %V", ctx->peer.name);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->name) {
        p = ngx_snprintf(buf, len, ", certificate: \"%s\"", ctx->name);
        len -= p - buf;
        buf = p;
    }

    return p;
}


#else


ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
    ngx_str_t *responder, ngx_uint_t verify)
{
    ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                  "\"ssl_stapling\" ignored, not supported");

    return NGX_OK;
}


ngx_int_t
ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    return NGX_OK;
}


ngx_int_t
ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
{
    ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                  "\"ssl_ocsp\" is not supported on this platform");

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    return NGX_OK;
}


ngx_int_t
ngx_ssl_ocsp_validate(ngx_connection_t *c)
{
    return NGX_OK;
}


ngx_int_t
ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s)
{
    return NGX_OK;
}


void
ngx_ssl_ocsp_cleanup(ngx_connection_t *c)
{
}


ngx_int_t
ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_OK;
}


#endif
