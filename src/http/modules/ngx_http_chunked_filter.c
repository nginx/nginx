
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_chunked_filter_init(ngx_cycle_t *cycle);


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


static ngx_int_t ngx_http_chunked_header_filter(ngx_http_request_t *r)
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


static ngx_int_t ngx_http_chunked_body_filter(ngx_http_request_t *r,
                                              ngx_chain_t *in)
{
    u_char       *chunk;
    size_t        size, len;
    ngx_buf_t    *b;
    ngx_chain_t   out, tail, *cl, *tl, **ll;

    if (in == NULL || !r->chunked) {
        return ngx_http_next_body_filter(r, in);
    }

    out.buf = NULL;
    ll = &out.next;

    size = 0;
    cl = in;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunk: %d", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        ngx_test_null(tl, ngx_alloc_chain_link(r->pool), NGX_ERROR);
        tl->buf = cl->buf;
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

        ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
        b->temporary = 1;
        b->pos = chunk;
        b->last = chunk + len;

        out.buf = b;
    }

    if (cl->buf->last_buf) {
        ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
        b->memory = 1;
        b->last_buf = 1;
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + 7;

        cl->buf->last_buf = 0;

        if (size == 0) {
            b->pos += 2;
            out.buf = b;
            out.next = NULL;

            return ngx_http_next_body_filter(r, &out);
        }

    } else {
        if (size == 0) {
            *ll = NULL;
            return ngx_http_next_body_filter(r, out.next);
        }

        ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;
    }

    tail.buf = b;
    tail.next = NULL;
    *ll = &tail;

    return ngx_http_next_body_filter(r, &out);
}


static ngx_int_t ngx_http_chunked_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_chunked_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_chunked_body_filter;

    return NGX_OK;
}
