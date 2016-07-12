
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_stream_complex_value_t  text;
} ngx_stream_return_srv_conf_t;


typedef struct {
    ngx_buf_t                   buf;
} ngx_stream_return_ctx_t;


static void ngx_stream_return_handler(ngx_stream_session_t *s);
static void ngx_stream_return_write_handler(ngx_event_t *ev);

static void *ngx_stream_return_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_return_commands[] = {

    { ngx_string("return"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_return,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_return_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_return_create_srv_conf,     /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_return_module = {
    NGX_MODULE_V1,
    &ngx_stream_return_module_ctx,         /* module context */
    ngx_stream_return_commands,            /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_return_handler(ngx_stream_session_t *s)
{
    ngx_str_t                      text;
    ngx_connection_t              *c;
    ngx_stream_return_ctx_t       *ctx;
    ngx_stream_return_srv_conf_t  *rscf;

    c = s->connection;

    c->log->action = "returning text";

    rscf = ngx_stream_get_module_srv_conf(s, ngx_stream_return_module);

    if (ngx_stream_complex_value(s, &rscf->text, &text) != NGX_OK) {
        ngx_stream_close_connection(c);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream return text: \"%V\"", &text);

    if (text.len == 0) {
        ngx_stream_close_connection(c);
        return;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_return_ctx_t));
    if (ctx == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_return_module);

    ctx->buf.pos = text.data;
    ctx->buf.last = text.data + text.len;

    c->write->handler = ngx_stream_return_write_handler;

    ngx_stream_return_write_handler(c->write);
}


static void
ngx_stream_return_write_handler(ngx_event_t *ev)
{
    ssize_t                   n;
    ngx_buf_t                *b;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_return_ctx_t  *ctx;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
        ngx_stream_close_connection(c);
        return;
    }

    if (ev->ready) {
        ctx = ngx_stream_get_module_ctx(s, ngx_stream_return_module);

        b = &ctx->buf;

        n = c->send(c, b->pos, b->last - b->pos);
        if (n == NGX_ERROR) {
            ngx_stream_close_connection(c);
            return;
        }

        if (n > 0) {
            b->pos += n;

            if (b->pos == b->last) {
                ngx_stream_close_connection(c);
                return;
            }
        }
    }

    if (ngx_handle_write_event(ev, 0) != NGX_OK) {
        ngx_stream_close_connection(c);
        return;
    }

    ngx_add_timer(ev, 5000);
}


static void *
ngx_stream_return_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_return_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_return_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_stream_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_return_srv_conf_t *rscf = conf;

    ngx_str_t                           *value;
    ngx_stream_core_srv_conf_t          *cscf;
    ngx_stream_compile_complex_value_t   ccv;

    if (rscf->text.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &rscf->text;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_return_handler;

    return NGX_CONF_OK;
}
