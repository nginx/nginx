
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static int ngx_http_chunked_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_chunked_filter_module_ctx = {
    NULL,                                  /* pre conf */

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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static int ngx_http_chunked_header_filter(ngx_http_request_t *r)
{
    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n == -1) {
        if (r->http_version < NGX_HTTP_VERSION_11) {
            r->keepalive = 0;

        } else {
            r->chunked = 1;
        }
    }

    return ngx_http_next_header_filter(r);
}


static int ngx_http_chunked_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char       *chunk;
    size_t        size, len;
    ngx_hunk_t   *h;
    ngx_chain_t   out, tail, *cl, *tl, **ll;

    if (in == NULL || !r->chunked) {
        return ngx_http_next_body_filter(r, in);
    }

    out.hunk = NULL;
    ll = &out.next;

    size = 0;
    cl = in;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunk: %d", ngx_hunk_size(cl->hunk));

        size += ngx_hunk_size(cl->hunk);

        ngx_test_null(tl, ngx_alloc_chain_link(r->pool), NGX_ERROR);
        tl->hunk = cl->hunk;
        *ll = tl;
        ll = &tl->next;

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        ngx_test_null(chunk, ngx_palloc(r->pool, 11), NGX_ERROR);
        len = ngx_snprintf((char *) chunk, 11, SIZE_T_X_FMT CRLF, size);

        ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
        h->pos = chunk;
        h->last = chunk + len;

        out.hunk = h;
    }

    if (cl->hunk->type & NGX_HUNK_LAST) {
        ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY|NGX_HUNK_LAST;
        h->pos = (u_char *) CRLF "0" CRLF CRLF;
        h->last = h->pos + 7;

        cl->hunk->type &= ~NGX_HUNK_LAST;

        if (size == 0) {
            h->pos += 2;
            out.hunk = h;
            out.next = NULL;

            return ngx_http_next_body_filter(r, &out);
        }

    } else {
        if (size == 0) {
            *ll = NULL;
            return ngx_http_next_body_filter(r, out.next);
        }

        ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY;
        h->pos = (u_char *) CRLF;
        h->last = h->pos + 2;
    }

    tail.hunk = h;
    tail.next = NULL;
    *ll = &tail;

    return ngx_http_next_body_filter(r, &out);
}


static int ngx_http_chunked_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_chunked_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_chunked_body_filter;

    return NGX_OK;
}
