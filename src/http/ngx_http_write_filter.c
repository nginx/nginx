
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct {
    ngx_chain_t  *out;
} ngx_http_write_filter_ctx_t;


static ngx_int_t ngx_http_write_filter_init(ngx_cycle_t *cycle);


ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE,
    &ngx_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_write_filter_init,            /* init module */
    NULL                                   /* init process */
};


ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                           last;
    off_t                         size, flush, sent;
    ngx_chain_t                  *cl, *ln, **ll, *chain;
    ngx_connection_t             *c;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_write_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r->main ? r->main : r,
                                  ngx_http_write_filter_module);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_write_filter_module,
                            sizeof(ngx_http_write_filter_ctx_t), NGX_ERROR);
    }

    size = 0;
    flush = 0;
    last = 0;
    ll = &ctx->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = ctx->out; cl; cl = cl->next) {
        ll = &cl->next;

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = size;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        ngx_alloc_link_and_set_buf(cl, ln->buf, r->pool, NGX_ERROR);
        *ll = cl;
        ll = &cl->next;

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = size;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    c = r->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%d f:" OFF_T_FMT " s:" OFF_T_FMT,
                   last, flush, size);

    clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                        ngx_http_core_module);

    /*
     * avoid the output if there is no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && flush == 0 && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

    if (c->write->delayed) {
        return NGX_AGAIN;
    }

    if (size == 0 && !c->buffered) {
        if (!last) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the http output chain is empty");
        }
        return NGX_OK;
    }

    sent = c->sent;

    chain = c->send_chain(c, ctx->out,
                          clcf->limit_rate ? clcf->limit_rate: OFF_T_MAX_VALUE);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %X", chain);

    if (clcf->limit_rate) {
        sent = c->sent - sent;
        c->write->delayed = 1;
        ngx_add_timer(r->connection->write,
                      (ngx_msec_t) (sent * 1000 / clcf->limit_rate));
    }

    if (chain == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ctx->out = chain;

    if (chain || c->buffered) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_write_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
