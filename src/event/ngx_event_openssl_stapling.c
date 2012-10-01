
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#ifdef SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB


static int ngx_ssl_certificate_status_callback(ngx_ssl_conn_t *ssl_conn,
    void *data);


ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    BIO            *bio;
    int             len;
    u_char         *p, *buf;
    ngx_str_t      *staple;
    OCSP_RESPONSE  *response;

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

    buf = ngx_pnalloc(cf->pool, len);
    if (buf == NULL) {
        goto failed;
    }

    p = buf;
    len = i2d_OCSP_RESPONSE(response, &p);
    if (len <= 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        goto failed;
    }

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    staple = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (staple == NULL) {
        return NGX_ERROR;
    }

    staple->data = buf;
    staple->len = len;

    SSL_CTX_set_tlsext_status_cb(ssl->ctx, ngx_ssl_certificate_status_callback);
    SSL_CTX_set_tlsext_status_arg(ssl->ctx, staple);

    return NGX_OK;

failed:

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    return NGX_ERROR;
}


static int
ngx_ssl_certificate_status_callback(ngx_ssl_conn_t *ssl_conn, void *data)
{
    u_char            *p;
    ngx_str_t         *staple;
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection(ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL certificate status callback");

    staple = data;

    /* we have to copy the staple as OpenSSL will free it by itself */

    p = OPENSSL_malloc(staple->len);
    if (p == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "OPENSSL_malloc() failed");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    ngx_memcpy(p, staple->data, staple->len);

    SSL_set_tlsext_status_ocsp_resp(ssl_conn, p, staple->len);

    return SSL_TLSEXT_ERR_OK;
}


#else


ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                  "\"ssl_stapling\" ignored, not supported");

    return NGX_OK;
}


#endif
