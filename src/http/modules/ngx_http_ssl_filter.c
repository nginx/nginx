
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#define NGX_DEFLAUT_CERTIFICATE      "cert.pem"
#define NGX_DEFLAUT_CERTIFICATE_KEY  "cert.pem"


typedef struct {
    ngx_flag_t   enable;
    ngx_str_t    certificate;
    ngx_str_t    certificate_key;

    SSL_CTX     *ssl_ctx;
} ngx_http_ssl_srv_conf_t;


typedef struct {
    SSL       *ssl;
} ngx_http_ssl_ctx_t;


static ngx_http_ssl_ctx_t *ngx_http_ssl_create_ctx(ngx_http_request_t *r);
static ngx_chain_t *ngx_http_ssl_write(ngx_http_request_t *r, ngx_chain_t *in,
                                       off_t limit);
static void ngx_http_ssl_error(ngx_uint_t level, ngx_log_t *log, int err,
                               char *fmt, ...);
static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
                                         void *parent, void *child);
static ngx_int_t ngx_http_ssl_filter_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_charset_filter_commands[] = {

    { ngx_string("ssl_"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_key),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_create_srv_conf,          /* create server configuration */
    ngx_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_filter_module = {
    NGX_MODULE,
    &ngx_http_ssl_filter_module_ctx,       /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_ssl_filter_init,              /* init module */
    NULL                                   /* init process */
};


ngx_int_t ngx_http_ssl_read(ngx_http_request_t *r, u_char *buf, size_t n)
{
    int                  rc;
    ngx_http_ssl_ctx_t  *ctx;
    ngx_http_log_ctx_t  *log_ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_filter_module);

    if (ctx == NULL) {
        ctx = ngx_http_ssl_create_ctx(r);

        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = SSL_read(ctx->ssl, buf, n);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "SSL_read: %d", rc);

    if (rc > 0) {
       return rc;
    }

    rc = SSL_get_error(ctx->ssl, rc);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "SSL_get_error: %d", rc);

    if (rc == SSL_ERROR_WANT_READ) {
        return NGX_AGAIN;
    }

#if 0
    if (rc == SSL_ERROR_WANT_WRITE) {
        return NGX_AGAIN;
    }
#endif

    if (!SSL_is_init_finished(ctx->ssl)) {
        log_ctx = (ngx_http_log_ctx_t *) r->connection->log->data;
        log_ctx->action = "SSL handshake";
    }

    if (rc == SSL_ERROR_ZERO_RETURN) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                       "client closed connection");

        SSL_set_shutdown(ctx->ssl, SSL_RECEIVED_SHUTDOWN);

        return NGX_SSL_ERROR;
    }

    if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "client sent plain HTTP request to HTTPS port");

        SSL_set_shutdown(ctx->ssl,
                         SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN);

        return NGX_SSL_HTTP_ERROR;
    }

    ngx_http_ssl_error(NGX_LOG_ALERT, r->connection->log, rc,
                       "SSL_read() failed");

    SSL_set_shutdown(ctx->ssl, SSL_RECEIVED_SHUTDOWN);

    return NGX_SSL_ERROR;
}


ngx_int_t ngx_http_ssl_writer(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_ssl_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_filter_module);

    if (in == NULL) {
        rc = SSL_shutdown(ctx->ssl);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "SSL_shutdown: %d", rc);

        if (rc == 0) {
            return NGX_AGAIN;
        }

        if (rc == 1) {
            SSL_free(ctx->ssl);
            return NGX_OK;
        }

        rc = SSL_get_error(ctx->ssl, rc);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "SSL_get_error: %d", rc);

        if (rc == SSL_ERROR_WANT_WRITE) {
            return NGX_AGAIN;
        }

        ngx_http_ssl_error(NGX_LOG_ALERT, r->connection->log, rc,
                           "SSL_shutdown() failed");

        return NGX_ERROR;
    }

    ch = ngx_http_ssl_write(r, ctx, in, 0);

    return NGX_OK;
}


static ngx_chain_t *ngx_http_ssl_write(ngx_http_request_t *r,
                                       ngx_http_ssl_ctx_t *ctx,
                                       ngx_chain_t *in,
                                       off_t limit)
{
    int                  rc;
    size_t               send, size;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_filter_module);

    send = 0;

    for (/* void */; in; in = in->next) {
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        size = in->buf->last - in->buf->pos;

        if (send + size > limit) {
            size = limit - send;
        }

        rc = SSL_write(ctx->ssl, in->buf->pos, size);

        if (rc > 0) {
            in->buf->pos += rc;

            if (rc == size) {
                continue;
            }

            r->connection->write->ready = 0;
            return in;
        }
    }

    return in;
}


static ngx_http_ssl_ctx_t *ngx_http_ssl_create_ctx(ngx_http_request_t *r)
{
    ngx_http_ssl_ctx_t       *ctx;
    ngx_http_ssl_srv_conf_t  *scf;

    ngx_http_create_ctx(r, ctx, ngx_http_ssl_filter_module,
                        sizeof(ngx_http_ssl_ctx_t), NULL);

    scf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_filter_module);

    ctx->ssl = SSL_new(scf->ssl_ctx);

    if (ctx->ssl == NULL) {
        ngx_http_ssl_error(NGX_LOG_ALERT, r->connection->log, 0,
                           "SSL_new() failed");
        return NULL;
    }

    if (SSL_set_fd(ctx->ssl, r->connection->fd) == 0) {
        ngx_http_ssl_error(NGX_LOG_ALERT, r->connection->log, 0,
                           "SSL_set_fd() failed");
        return NULL;
    }

    SSL_set_accept_state(ctx->ssl);

    return ctx;
}


void ngx_http_ssl_close_connection(SSL *ssl, ngx_log_t *log)
{
    int  rc;

    SSL_free(ssl);
}


static void ngx_http_ssl_error(ngx_uint_t level, ngx_log_t *log, int err,
                               char *fmt, ...)
{
    int      len;
    char     errstr[NGX_MAX_CONF_ERRSTR];
    va_list  args;

    va_start(args, fmt);
    len = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    errstr[len++] = ' ';
    errstr[len++] = '(';
    errstr[len++] = 'S';
    errstr[len++] = 'S';
    errstr[len++] = 'L';
    errstr[len++] = ':';
    errstr[len++] = ' ';

    ERR_error_string_n(ERR_get_error(), errstr + len, sizeof(errstr) - len - 1);

    ngx_log_error(level, log, 0, "%s)", errstr);
}


static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *scf;

    if (!(scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    scf->enable = NGX_CONF_UNSET;

    return scf;
}


static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
                                         void *parent, void *child)
{
    ngx_http_ssl_srv_conf_t *prev = parent;
    ngx_http_ssl_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_str_value(conf->certificate, prev->certificate,
                             NGX_DEFLAUT_CERTIFICATE);

    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key,
                             NGX_DEFLAUT_CERTIFICATE_KEY);

    /* STUB: where to move ??? */
    SSL_library_init();
    SSL_load_error_strings();

    /* TODO: inherit ssl_ctx */

    /* TODO: configure methods */

    conf->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    if (conf->ssl_ctx == NULL) {
        ngx_http_ssl_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_new() failed");
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_use_certificate_file(conf->ssl_ctx, conf->certificate.data,
                                     SSL_FILETYPE_PEM) == 0) {
        ngx_http_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                           "SSL_CTX_use_certificate_file() failed");
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(conf->ssl_ctx, conf->certificate_key.data,
                                    SSL_FILETYPE_PEM) == 0) {
        ngx_http_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                           "SSL_CTX_use_PrivateKey_file() failed");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_ssl_filter_init(ngx_cycle_t *cycle)
{
#if 0
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssl_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssl_body_filter;
#endif

    return NGX_OK;
}
