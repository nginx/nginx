
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_bufs_t  bufs;
} ngx_http_copy_filter_conf_t;


static void *ngx_http_copy_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_copy_filter_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_copy_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_copy_filter_commands[] = {

    { ngx_string("output_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_copy_filter_conf_t, bufs),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_copy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_copy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_copy_filter_create_conf,      /* create location configuration */
    ngx_http_copy_filter_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_copy_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_copy_filter_module_ctx,      /* module context */
    ngx_http_copy_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_body_filter_pt    ngx_http_next_filter;


static ngx_int_t
ngx_http_copy_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_output_chain_ctx_t       *ctx;
    ngx_http_copy_filter_conf_t  *conf;

    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "copy filter: \"%V?%V\"", &r->uri, &r->args);

    ctx = ngx_http_get_module_ctx(r, ngx_http_copy_filter_module);

    if (ctx == NULL) {
        conf = ngx_http_get_module_loc_conf(r, ngx_http_copy_filter_module);

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_output_chain_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_copy_filter_module);

        ctx->sendfile = c->sendfile;
        ctx->need_in_memory = r->main_filter_need_in_memory
                              || r->filter_need_in_memory;
        ctx->need_in_temp = r->filter_need_temporary;

        ctx->pool = r->pool;
        ctx->bufs = conf->bufs;
        ctx->tag = (ngx_buf_tag_t) &ngx_http_copy_filter_module;

        ctx->output_filter = (ngx_output_chain_filter_pt) ngx_http_next_filter;
        ctx->filter_ctx = r;

        r->request_output = 1;
    }

    rc = ngx_output_chain(ctx, in);

    if (!c->destroyed) {

        if (ctx->in == NULL) {
            r->buffered &= ~NGX_HTTP_COPY_BUFFERED;
        } else {
            r->buffered |= NGX_HTTP_COPY_BUFFERED;
        }

        if (r != r->main) {
            r->out = ctx->in;
        }

#if (NGX_DEBUG)
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "copy filter: %i \"%V?%V\"", rc, &r->uri, &r->args);
#endif

    }

    return rc;
}


static void *
ngx_http_copy_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_copy_filter_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_copy_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->bufs.num = 0;

    return conf;
}


static char *
ngx_http_copy_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_copy_filter_conf_t *prev = parent;
    ngx_http_copy_filter_conf_t *conf = child;

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 1, 32768);

    return NULL;
}


static ngx_int_t
ngx_http_copy_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_copy_filter;

    return NGX_OK;
}

