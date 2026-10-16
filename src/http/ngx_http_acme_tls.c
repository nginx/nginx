/*
 * Copyright (C) nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HTTP_ACME_TLS && NGX_HTTP_SSL)

typedef struct {
    ngx_http_upstream_conf_t   upstream;
} ngx_http_acme_tls_loc_conf_t;

typedef struct {
    ngx_http_upstream_t       *upstream;
    ngx_buf_t                 *ssl_preread_buf;
} ngx_http_acme_tls_ctx_t;


static char *ngx_http_acme_tls_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_acme_tls_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_acme_tls_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void *ngx_http_acme_tls_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_acme_tls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_acme_tls_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_acme_tls_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_acme_tls_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_acme_tls_process_header(ngx_http_request_t *r);
static void ngx_http_acme_tls_abort_request(ngx_http_request_t *r);
static void ngx_http_acme_tls_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_acme_tls_send_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_acme_tls_input_filter_init(void *data);
static ngx_int_t ngx_http_acme_tls_input_filter(void *data, ssize_t bytes);


static ngx_command_t ngx_http_acme_tls_commands[] = {

    { ngx_string("acme_tls"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_acme_tls_srv_conf_t, mode),
      &(ngx_conf_enum_t[]) {
          { ngx_string("off"), NGX_HTTP_ACME_TLS_MODE_OFF },
          { ngx_string("internal"), NGX_HTTP_ACME_TLS_MODE_INTERNAL },
          { ngx_string("proxy"), NGX_HTTP_ACME_TLS_MODE_PROXY },
          { ngx_null_string, 0 }
      }},

    { ngx_string("acme_tls_pass"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_acme_tls_pass,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("acme_tls_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_acme_tls_srv_conf_t, upstream_conf.connect_timeout),
      NULL },

    { ngx_string("acme_tls_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_acme_tls_srv_conf_t, upstream_conf.send_timeout),
      NULL },

    { ngx_string("acme_tls_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_acme_tls_srv_conf_t, upstream_conf.read_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_acme_tls_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_http_acme_tls_create_srv_conf, /* create server configuration */
    ngx_http_acme_tls_merge_srv_conf,  /* merge server configuration */

    ngx_http_acme_tls_create_loc_conf, /* create location configuration */
    ngx_http_acme_tls_merge_loc_conf   /* merge location configuration */
};


ngx_module_t ngx_http_acme_tls_module = {
    NGX_MODULE_V1,
    &ngx_http_acme_tls_module_ctx,     /* module context */
    ngx_http_acme_tls_commands,        /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


void
ngx_http_acme_tls_proxy(ngx_connection_t *c)
{
    ngx_http_request_t           *r;
    ngx_http_acme_tls_srv_conf_t *ascf;
    ngx_http_connection_t        *hc;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, 
                   "acme-tls/1 alpn detected, checking server configuration");

    hc = c->data;
    
    /* Get server configuration for this server block */
    ascf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_acme_tls_module);
    
    switch (ascf->mode) {
        case NGX_HTTP_ACME_TLS_MODE_OFF:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "acme-tls: mode=off, closing connection");
            ngx_http_close_connection(c);
            return;
            
        case NGX_HTTP_ACME_TLS_MODE_INTERNAL:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "acme-tls: mode=internal, deferring to future ACME module");
            /* TODO: Call future ACME module handler */
            ngx_http_close_connection(c);  /* For now, close connection */
            return;
            
        case NGX_HTTP_ACME_TLS_MODE_PROXY:
            if (ascf->upstream.len == 0) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "acme-tls: proxy mode but no upstream configured");
                ngx_http_close_connection(c);
                return;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "acme-tls: mode=proxy, upstream=%V", &ascf->upstream);
            break;
            
        default:
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "acme-tls: invalid mode %ui", ascf->mode);
            ngx_http_close_connection(c);
            return;
    }

    /* Create a minimal HTTP request for upstream processing */
    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    /* Set up minimal request structure for ACME-TLS proxy */
    r->method = NGX_HTTP_GET;  /* Doesn't matter for raw proxy */
    r->method_name = ngx_http_get_method;
    r->http_version = NGX_HTTP_VERSION_11;
    
    /* Initialize upstream immediately */
    if (ngx_http_acme_tls_handler(r) != NGX_OK) {
        ngx_http_close_connection(c);
    }
}


static void *
ngx_http_acme_tls_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_acme_tls_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_acme_tls_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_CONF_UNSET_UINT;
    conf->upstream_conf.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_acme_tls_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_acme_tls_srv_conf_t *prev = parent;
    ngx_http_acme_tls_srv_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, NGX_HTTP_ACME_TLS_MODE_OFF);
    ngx_conf_merge_str_value(conf->upstream, prev->upstream, "");
    
    ngx_conf_merge_msec_value(conf->upstream_conf.connect_timeout,
                              prev->upstream_conf.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream_conf.send_timeout,
                              prev->upstream_conf.send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream_conf.read_timeout,
                              prev->upstream_conf.read_timeout, 60000);
    ngx_conf_merge_size_value(conf->upstream_conf.buffer_size,
                              prev->upstream_conf.buffer_size, 8192);

    return NGX_CONF_OK;
}


static void *
ngx_http_acme_tls_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_acme_tls_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_acme_tls_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* Set upstream defaults */
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_acme_tls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_acme_tls_loc_conf_t *prev = parent;
    ngx_http_acme_tls_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);
    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size, 8192);

    return NGX_CONF_OK;
}


static char *
ngx_http_acme_tls_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_acme_tls_srv_conf_t *ascf = conf;
    ngx_str_t                    *value;
    ngx_url_t                     u;

    if (ascf->upstream.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"acme_tls_pass\" directive", u.err);
        }
        return NGX_CONF_ERROR;
    }

    ascf->upstream = value[1];

    /* Automatically set mode to proxy when acme_tls_pass is used */
    if (ascf->mode == NGX_CONF_UNSET_UINT) {
        ascf->mode = NGX_HTTP_ACME_TLS_MODE_PROXY;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_acme_tls_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_upstream_t          *u;
    ngx_http_acme_tls_ctx_t      *ctx;
    ngx_http_acme_tls_srv_conf_t *ascf;

    /* Get the server configuration for upstream destination */
    ascf = ngx_http_get_module_srv_conf(r, ngx_http_acme_tls_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_acme_tls_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_acme_tls_module);

    u = r->upstream;
    ctx->upstream = u;

    /* Configure upstream for raw TCP proxy */
    u->conf = &ascf->upstream_conf;
    u->create_request = ngx_http_acme_tls_create_request;
    u->reinit_request = ngx_http_acme_tls_reinit_request;
    u->process_header = ngx_http_acme_tls_process_header;
    u->abort_request = ngx_http_acme_tls_abort_request;
    u->finalize_request = ngx_http_acme_tls_finalize_request;

    /* Set up input filter for raw data */
    u->input_filter_init = ngx_http_acme_tls_input_filter_init;
    u->input_filter = ngx_http_acme_tls_input_filter;
    u->input_filter_ctx = ctx;

    /* Copy SSL preread buffer if available */
    if (r->connection->ssl && r->connection->ssl->buffer) {
        ngx_buf_t *ssl_buf = r->connection->ssl->buffer;
        if (ssl_buf->pos < ssl_buf->last) {
            size_t len = ssl_buf->last - ssl_buf->pos;
            ctx->ssl_preread_buf = ngx_create_temp_buf(r->pool, len);
            if (ctx->ssl_preread_buf) {
                ngx_memcpy(ctx->ssl_preread_buf->start, ssl_buf->pos, len);
                ctx->ssl_preread_buf->last += len;
                ssl_buf->pos = ssl_buf->last; /* Mark as consumed */
            }
        }
    }

    r->state = 0;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_acme_tls_create_request(ngx_http_request_t *r)
{
    /* For raw TCP proxy, we don't send HTTP request - just forward data */
    r->upstream->request_bufs = NULL;
    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_tls_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_tls_process_header(ngx_http_request_t *r)
{
    /* For raw TCP proxy, there are no HTTP headers to process */
    r->upstream->headers_in.status_n = 200;
    r->upstream->state->status = 200;
    return NGX_OK;
}


static void
ngx_http_acme_tls_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort acme-tls request");
}


static void
ngx_http_acme_tls_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize acme-tls request");
}


static ngx_int_t
ngx_http_acme_tls_input_filter_init(void *data)
{
    ngx_http_acme_tls_ctx_t *ctx = data;
    ngx_http_request_t      *r;
    
    r = ctx->upstream->request;
    
    /* If we have SSL preread buffer, send it first */
    if (ctx->ssl_preread_buf && ctx->ssl_preread_buf->pos < ctx->ssl_preread_buf->last) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "acme-tls: forwarding %uz bytes from SSL preread buffer",
                      ctx->ssl_preread_buf->last - ctx->ssl_preread_buf->pos);
    }
    
    return NGX_OK;
}


static ngx_int_t
ngx_http_acme_tls_input_filter(void *data, ssize_t bytes)
{
    ngx_http_acme_tls_ctx_t *ctx = data;
    ngx_http_upstream_t     *u;
    ngx_chain_t             *cl;
    ngx_buf_t               *b;
    
    u = ctx->upstream;
    
    /* Forward all data transparently */
    for (cl = u->buffer.bufs; cl; cl = cl->next) {
        b = cl->buf;
        b->last_buf = (cl->next == NULL);
        b->last_in_chain = b->last_buf;
        b->flush = 1;
    }
    
    return NGX_OK;
}

#endif /* NGX_HTTP_ACME_TLS && NGX_HTTP_SSL */