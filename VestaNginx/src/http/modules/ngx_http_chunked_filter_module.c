
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
} ngx_http_chunked_filter_ctx_t;


static ngx_int_t ngx_http_chunked_filter_init(ngx_conf_t *cf);
static ngx_chain_t *ngx_http_chunked_create_trailers(ngx_http_request_t *r,
    ngx_http_chunked_filter_ctx_t *ctx);


static ngx_http_module_t  ngx_http_chunked_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_chunked_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_chunked_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_chunked_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_chunked_header_filter(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_chunked_filter_ctx_t  *ctx;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status < NGX_HTTP_OK
        || r != r->main
        || r->method == NGX_HTTP_HEAD)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n == -1
        || r->expect_trailers)
    {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (r->http_version >= NGX_HTTP_VERSION_11
            && clcf->chunked_transfer_encoding)
        {
            if (r->expect_trailers) {
                ngx_http_clear_content_length(r);
            }

            r->chunked = 1;

            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_filter_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }

            ngx_http_set_ctx(r, ctx, ngx_http_chunked_filter_module);

        } else if (r->headers_out.content_length_n == -1) {
            r->keepalive = 0;
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_chunked_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                         *chunk;
    off_t                           size;
    ngx_int_t                       rc;
    ngx_buf_t                      *b;
    ngx_chain_t                    *out, *cl, *tl, **ll;
    ngx_http_chunked_filter_ctx_t  *ctx;

    if (in == NULL || !r->chunked || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_chunked_filter_module);

    out = NULL;
    ll = &out;

    size = 0;
    cl = in;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return NGX_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = ngx_sprintf(chunk, "%xO" CRLF, size);

        tl->next = out;
        out = tl;
    }

    if (cl->buf->last_buf) {
        tl = ngx_http_chunked_create_trailers(r, ctx);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            tl->buf->pos += 2;
        }

    } else if (size > 0) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    rc = ngx_http_next_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_chunked_filter_module);

    return rc;
}


static ngx_chain_t *
ngx_http_chunked_create_trailers(ngx_http_request_t *r,
    ngx_http_chunked_filter_ctx_t *ctx)
{
    size_t            len;
    ngx_buf_t        *b;
    ngx_uint_t        i;
    ngx_chain_t      *cl;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    len = 0;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1
               + header[i].value.len + sizeof(CRLF) - 1;
    }

    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;

    b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
    b->temporary = 0;
    b->memory = 1;
    b->last_buf = 1;

    if (len == 0) {
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + sizeof(CRLF "0" CRLF CRLF) - 1;
        return cl;
    }

    len += sizeof(CRLF "0" CRLF CRLF) - 1;

    b->pos = ngx_palloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = b->pos;

    *b->last++ = CR; *b->last++ = LF;
    *b->last++ = '0';
    *b->last++ = CR; *b->last++ = LF;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http trailer: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    return cl;
}


static ngx_int_t
ngx_http_chunked_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_chunked_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_chunked_body_filter;

    return NGX_OK;
}
