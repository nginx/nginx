
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_postpone_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_postpone_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_postpone_filter_module_ctx,  /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_postpone_filter_init,         /* init module */
    NULL                                   /* init process */
};


static ngx_http_output_body_filter_pt    ngx_http_next_filter;


static ngx_int_t
ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_chain_t                   *out;
    ngx_http_request_t            *mr;
    ngx_http_postponed_request_t  *pr, **ppr;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http postpone filter \"%V\" %p", &r->uri, in);

    if (r->connection->closed) {

        if (r->postponed) {
            r->postponed = r->postponed->next;
        }

        return NGX_ERROR;
    }

    if (r != r->connection->data || (r->postponed && in)) {

        if (r->postponed) {
            for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

            ppr = pr->request ? &pr->next : NULL;

        } else {
            ppr = &r->postponed;
#if (NGX_SUPPRESS_WARN)
            pr = NULL;
#endif
        }

        if (ppr) {
            pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
            if (pr == NULL) {
                return NGX_ERROR;
            }

            *ppr = pr;

            pr->request = NULL;
            pr->out = NULL;
            pr->next = NULL;
        }

        if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (r != r->connection->data || r->postponed->request) {
            return NGX_AGAIN;
        }
    }

    if (r->postponed) {
        out = r->postponed->out;
        r->postponed = r->postponed->next;

    } else {
        out = in;
    }

    mr = r->main ? r->main : r;

    if (out == NULL && mr->out == NULL && !mr->connection->buffered) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http postpone filter out \"%V\"", &r->uri);

    rc = ngx_http_next_filter(mr, out);

    if (rc == NGX_ERROR) {
        /* NGX_ERROR may be returned by any filter */
        r->connection->closed = 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_postpone_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_postpone_filter;

    return NGX_OK;
}
