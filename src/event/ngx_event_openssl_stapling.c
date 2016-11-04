
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
    ngx_str_t                    host;
    ngx_str_t                    uri;
    in_port_t                    port;

    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;

    time_t                       valid;
    time_t                       refresh;

    unsigned                     verify:1;
    unsigned                     loading:1;
} ngx_ssl_stapling_t;


typedef struct ngx_ssl_ocsp_ctx_s  ngx_ssl_ocsp_ctx_t;

struct ngx_ssl_ocsp_ctx_s {
    X509                        *cert;
    X509                        *issuer;

    ngx_uint_t                   naddrs;

    ngx_addr_t                  *addrs;
    ngx_str_t                    host;
    ngx_str_t                    uri;
    in_port_t                    port;

    ngx_resolver_t              *resolver;
    ngx_msec_t                   resolver_timeout;

    ngx_msec_t                   timeout;

    void                       (*handler)(ngx_ssl_ocsp_ctx_t *r);
    void                        *data;

    ngx_buf_t                   *request;
    ngx_buf_t                   *response;
    ngx_peer_connection_t        peer;

    ngx_int_t                  (*process)(ngx_ssl_ocsp_ctx_t *r);

    ngx_uint_t                   state;

    ngx_uint_t                   code;
    ngx_uint_t                   count;

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

static ngx_ssl_ocsp_ctx_t *ngx_ssl_ocsp_start(void);
static void ngx_ssl_ocsp_done(ngx_ssl_ocsp_ctx_t *ctx);
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

    staple->ssl_ctx = ssl->ctx;
    staple->timeout = 60000;
    staple->verify = verify;
    staple->cert = cert;

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

    bio = BIO_new_file((char *) file->data, "r");
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
    STACK_OF(X509)  *chain;

    cert = staple->cert;

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
    /* OpenSSL 1.0.2+ */
    SSL_CTX_select_current_cert(ssl->ctx, cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
    /* OpenSSL 1.0.1+ */
    SSL_CTX_get_extra_chain_certs(ssl->ctx, &chain);
#else
    chain = ssl->ctx->extra_certs;
#endif

    n = sk_X509_num(chain);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: %d extra certs", n);

    for (i = 0; i < n; i++) {
        issuer = sk_X509_value(chain, i);
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
                      "\"ssl_stapling\" ignored, issuer certificate not found");
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
    ngx_url_t                  u;
    char                      *s;
    ngx_str_t                  rsp;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (responder->len == 0) {

        /* extract OCSP responder URL from certificate */

        aia = X509_get1_ocsp(staple->cert);
        if (aia == NULL) {
            ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate");
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
                          "no OCSP responder URL in the certificate");
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
                      "invalid URL prefix in OCSP responder \"%V\"", &u.url);
        return NGX_DECLINED;
    }

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "%s in OCSP responder \"%V\"", u.err, &u.url);
            return NGX_DECLINED;
        }

        return NGX_ERROR;
    }

    staple->addrs = u.addrs;
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

    ctx = ngx_ssl_ocsp_start();
    if (ctx == NULL) {
        return;
    }

    ctx->cert = staple->cert;
    ctx->issuer = staple->issuer;

    ctx->addrs = staple->addrs;
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
#if OPENSSL_VERSION_NUMBER >= 0x0090707fL
    const
#endif
    u_char                *p;
    int                    n;
    size_t                 len;
    time_t                 now, valid;
    ngx_str_t              response;
    X509_STORE            *store;
    STACK_OF(X509)        *chain;
    OCSP_CERTID           *id;
    OCSP_RESPONSE         *ocsp;
    OCSP_BASICRESP        *basic;
    ngx_ssl_stapling_t    *staple;
    ASN1_GENERALIZEDTIME  *thisupdate, *nextupdate;

    staple = ctx->data;
    now = ngx_time();
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

    store = SSL_CTX_get_cert_store(staple->ssl_ctx);
    if (store == NULL) {
        ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        goto error;
    }

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
    /* OpenSSL 1.0.2+ */
    SSL_CTX_select_current_cert(staple->ssl_ctx, ctx->cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
    /* OpenSSL 1.0.1+ */
    SSL_CTX_get_extra_chain_certs(staple->ssl_ctx, &chain);
#else
    chain = staple->ssl_ctx->extra_certs;
#endif

    if (OCSP_basic_verify(basic, chain, store,
                          staple->verify ? OCSP_TRUSTOTHER : OCSP_NOVERIFY)
        != 1)
    {
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

    if (OCSP_resp_find_status(basic, id, &n, NULL, NULL,
                              &thisupdate, &nextupdate)
        != 1)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "certificate status not found in the OCSP response");
        goto error;
    }

    if (n != V_OCSP_CERTSTATUS_GOOD) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "certificate status \"%s\" in the OCSP response",
                      OCSP_cert_status_str(n));
        goto error;
    }

    if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
                      "OCSP_check_validity() failed");
        goto error;
    }

    if (nextupdate) {
        valid = ngx_ssl_stapling_time(nextupdate);
        if (valid == (time_t) NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "invalid nextUpdate time in certificate status");
            goto error;
        }

    } else {
        valid = NGX_MAX_TIME_T_VALUE;
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(ocsp);

    id = NULL;
    basic = NULL;
    ocsp = NULL;

    /* copy the response to memory not in ctx->pool */

    response.len = len;
    response.data = ngx_alloc(response.len, ctx->log);

    if (response.data == NULL) {
        goto error;
    }

    ngx_memcpy(response.data, ctx->response->pos, response.len);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp response, %s, %uz",
                   OCSP_cert_status_str(n), response.len);

    if (staple->staple.data) {
        ngx_free(staple->staple.data);
    }

    staple->staple = response;
    staple->valid = valid;

    /*
     * refresh before the response expires,
     * but not earlier than in 5 minutes, and at least in an hour
     */

    staple->loading = 0;
    staple->refresh = ngx_max(ngx_min(valid - 300, now + 3600), now + 300);

    ngx_ssl_ocsp_done(ctx);
    return;

error:

    staple->loading = 0;
    staple->refresh = now + 300;

    if (id) {
        OCSP_CERTID_free(id);
    }

    if (basic) {
        OCSP_BASICRESP_free(basic);
    }

    if (ocsp) {
        OCSP_RESPONSE_free(ocsp);
    }

    ngx_ssl_ocsp_done(ctx);
}


static time_t
ngx_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time)
{
    u_char  *value;
    size_t   len;
    time_t   time;
    BIO     *bio;

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

    time = ngx_parse_http_time(value, len);

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


static ngx_ssl_ocsp_ctx_t *
ngx_ssl_ocsp_start(void)
{
    ngx_log_t           *log;
    ngx_pool_t          *pool;
    ngx_ssl_ocsp_ctx_t  *ctx;

    pool = ngx_create_pool(2048, ngx_cycle->log);
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

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect");

    /* TODO: use all ip addresses */

    ctx->peer.sockaddr = ctx->addrs[0].sockaddr;
    ctx->peer.socklen = ctx->addrs[0].socklen;
    ctx->peer.name = &ctx->addrs[0].name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect peer done");

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_ssl_ocsp_error(ctx);
        return;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = ctx->pool;

    ctx->peer.connection->read->handler = ngx_ssl_ocsp_read_handler;
    ctx->peer.connection->write->handler = ngx_ssl_ocsp_write_handler;

    ctx->process = ngx_ssl_ocsp_process_status_line;

    ngx_add_timer(ctx->peer.connection->read, ctx->timeout);
    ngx_add_timer(ctx->peer.connection->write, ctx->timeout);

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
        ngx_ssl_ocsp_error(ctx);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = ngx_send(c, ctx->request->pos, size);

    if (n == NGX_ERROR) {
        ngx_ssl_ocsp_error(ctx);
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

    if (!wev->timer_set) {
        ngx_add_timer(wev, ctx->timeout);
    }
}


static void
ngx_ssl_ocsp_read_handler(ngx_event_t *rev)
{
    ssize_t            n, size;
    ngx_int_t          rc;
    ngx_ssl_ocsp_ctx_t    *ctx;
    ngx_connection_t  *c;

    c = rev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0,
                   "ssl ocsp read handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "OCSP responder timed out");
        ngx_ssl_ocsp_error(ctx);
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
                ngx_ssl_ocsp_error(ctx);
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

    ngx_ssl_ocsp_error(ctx);
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
#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp status line \"%*s\"",
                       ctx->response->pos - ctx->response->start,
                       ctx->response->start);
#endif

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

            ctx->code = ctx->code * 10 + ch - '0';

            if (++ctx->count == 3) {
                state = sw_space_after_status;
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
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            switch (ch) {
            case LF:
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
    u_char      c, ch, *p;
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


static u_char *
ngx_ssl_ocsp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_ssl_ocsp_ctx_t  *ctx;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    ctx = log->data;

    if (ctx) {
        p = ngx_snprintf(p, len, ", responder: %V", &ctx->host);
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


#endif
