
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

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

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
        if (!(cl = ngx_alloc_chain_link(r->pool))) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = size;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    c = r->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%d f:%O s:%O", last, flush, size);

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
        if (last) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    sent = c->sent;

    chain = c->send_chain(c, ctx->out, clcf->limit_rate);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

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

    if (chain || (last && c->buffered)) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_write_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
