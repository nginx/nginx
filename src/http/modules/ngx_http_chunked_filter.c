
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static int ngx_http_chunked_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_chunked_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_chunked_filter_module = {
    NGX_MODULE,
    &ngx_http_chunked_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_chunked_filter_init,          /* init module */
    NULL                                   /* init child */
};


static int (*next_header_filter) (ngx_http_request_t *r);
static int (*next_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static int ngx_http_chunked_header_filter(ngx_http_request_t *r)
{
    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return next_header_filter(r);
    }

    if (r->headers_out.content_length == -1) {
        if (r->http_version < NGX_HTTP_VERSION_11) {
            r->keepalive = 0;

        } else {
            r->chunked = 1;
        }
    }

    return next_header_filter(r);
}


static int ngx_http_chunked_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    char         *chunk;
    size_t        size, len;
    ngx_hunk_t   *h;
    ngx_chain_t  *out, *ce, *te, **le;

    if (in == NULL || !r->chunked) {
        return next_body_filter(r, in);
    }

    ngx_test_null(out, ngx_alloc_chain_entry(r->pool), NGX_ERROR);
    le = &out->next;

    size = 0;
    ce = in;

    for ( ;; ) {

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            size += ce->hunk->last - ce->hunk->pos;
        } else {
            size += (size_t) (ce->hunk->file_last - ce->hunk->file_pos);
        }

        ngx_test_null(te, ngx_alloc_chain_entry(r->pool), NGX_ERROR);
        te->hunk = ce->hunk;
        *le = te;
        le = &te->next;

        if (ce->next == NULL) {
            break;
        }

        ce = ce->next;
    }

    ngx_test_null(chunk, ngx_palloc(r->pool, 11), NGX_ERROR);
    len = ngx_snprintf(chunk, 11, SIZEX_FMT CRLF, size);

    ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
    h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
    h->pos = chunk;
    h->last = chunk + len;

    out->hunk = h;

    ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);

    if (ce->hunk->type & NGX_HUNK_LAST) {
        ce->hunk->type &= ~NGX_HUNK_LAST;
        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY|NGX_HUNK_LAST;
        h->pos = CRLF "0" CRLF CRLF;
        h->last = h->pos + 7;

    } else {
        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY;
        h->pos = CRLF;
        h->last = h->pos + 2;
    }

    ngx_test_null(te, ngx_alloc_chain_entry(r->pool), NGX_ERROR);
    te->hunk = h;
    te->next = NULL;
    *le = te;

    return next_body_filter(r, out);
}


static int ngx_http_chunked_filter_init(ngx_cycle_t *cycle)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_chunked_header_filter;

    next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_chunked_body_filter;

    return NGX_OK;
}
