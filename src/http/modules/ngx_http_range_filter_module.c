
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_multirange_slicing.h"

/*
 * the single part format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: image/jpeg" CRLF
 * "Content-Length: SIZE" CRLF
 * "Content-Range: bytes START-END/SIZE" CRLF
 * CRLF
 * ... data ...
 *
 *
 * the multipart format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: multipart/byteranges; boundary=0123456789" CRLF
 * CRLF
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START0-END0/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START1-END1/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789--" CRLF
 */



typedef struct {
    off_t        offset;
    ngx_str_t    boundary_header;
    ngx_array_t  ranges;
} ngx_http_range_filter_ctx_t;


static ngx_int_t ngx_http_range_parse(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_uint_t ranges);
static ngx_int_t ngx_http_range_singlepart_header(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx);
static ngx_int_t ngx_http_range_multipart_header(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx);
static ngx_int_t ngx_http_range_not_satisfiable(ngx_http_request_t *r);
static ngx_int_t ngx_http_range_test_overlapped(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_range_singlepart_body(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_range_multipart_body(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_multirange_body(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_multirange_header(ngx_http_request_t *r,
        ngx_http_range_filter_ctx_t *ctx);
static ngx_int_t ngx_http_multirange_slice_range(ngx_http_request_t *r,
        ngx_http_slice_range_t **slice_range);


static ngx_int_t ngx_http_range_header_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_range_body_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_range_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_range_header_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_range_header_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_range_header_filter_module_ctx, /* module context */
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


static ngx_http_module_t  ngx_http_range_body_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_range_body_filter_init,       /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_range_body_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_range_body_filter_module_ctx, /* module context */
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
ngx_http_range_header_filter(ngx_http_request_t *r)
{
    time_t                        if_range_time;
    ngx_str_t                    *if_range, *etag;
    ngx_uint_t                    ranges;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_range_filter_ctx_t  *ctx;

    if (r->http_version < NGX_HTTP_VERSION_10
        || r->headers_out.status != NGX_HTTP_OK
        || (r != r->main && !r->subrequest_ranges)
        || r->headers_out.content_length_n == -1
        || !r->allow_ranges)
    {
        return ngx_http_next_header_filter(r);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->max_ranges == 0) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6)
           != 0)
    {
        goto next_filter;
    }

    if (r->headers_in.if_range) {

        if_range = &r->headers_in.if_range->value;

        if (if_range->len >= 2 && if_range->data[if_range->len - 1] == '"') {

            if (r->headers_out.etag == NULL) {
                goto next_filter;
            }

            etag = &r->headers_out.etag->value;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ir:%V etag:%V", if_range, etag);

            if (if_range->len != etag->len
                || ngx_strncmp(if_range->data, etag->data, etag->len) != 0)
            {
                goto next_filter;
            }

            goto parse;
        }

        if (r->headers_out.last_modified_time == (time_t) -1) {
            goto next_filter;
        }

        if_range_time = ngx_parse_http_time(if_range->data, if_range->len);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http ir:%T lm:%T",
                       if_range_time, r->headers_out.last_modified_time);

        if (if_range_time != r->headers_out.last_modified_time) {
            goto next_filter;
        }
    }

parse:

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_range_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->offset = r->headers_out.content_offset;
    ranges = /* r->single_range */ 0 ? 1 : clcf->max_ranges;

    switch (ngx_http_range_parse(r, ctx, ranges)) {

    case NGX_OK:
        ngx_http_set_ctx(r, ctx, ngx_http_range_body_filter_module);

        r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
        r->headers_out.status_line.len = 0;

        if (ctx->ranges.nelts == 1) {
            return ngx_http_range_singlepart_header(r, ctx);
        }

        if (0) { return ngx_http_range_multipart_header(r, ctx); }
        return ngx_http_multirange_header(r, ctx);

    case NGX_HTTP_RANGE_NOT_SATISFIABLE:
        return ngx_http_range_not_satisfiable(r);

    case NGX_ERROR:
        return NGX_ERROR;

    default: /* NGX_DECLINED */
        break;
    }

next_filter:

    r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.accept_ranges == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.accept_ranges->hash = 1;
    r->headers_out.accept_ranges->next = NULL;
    ngx_str_set(&r->headers_out.accept_ranges->key, "Accept-Ranges");
    ngx_str_set(&r->headers_out.accept_ranges->value, "bytes");

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_range_parse(ngx_http_request_t *r, ngx_http_range_filter_ctx_t *ctx,
    ngx_uint_t ranges)
{
    u_char                       *p;
    off_t                         start, end, size, content_length, cutoff,
                                  cutlim;
    ngx_uint_t                    suffix;
    ngx_http_range_t             *range;
    ngx_http_range_filter_ctx_t  *mctx;

    if (r != r->main) {
        mctx = ngx_http_get_module_ctx(r->main,
                                       ngx_http_range_body_filter_module);
        if (mctx) {
            ctx->ranges = mctx->ranges;
            return NGX_OK;
        }
    }

    if (ngx_array_init(&ctx->ranges, r->pool, 1, sizeof(ngx_http_range_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = r->headers_in.range->value.data + 6;
    size = 0;
    content_length = r->headers_out.content_length_n;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;

        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p >= '0' && *p <= '9') {
                if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }

                start = start * 10 + (*p++ - '0');
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                end = content_length;
                goto found;
            }

        } else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            end = end * 10 + (*p++ - '0');
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        if (suffix) {
            start = (end < content_length) ? content_length - end : 0;
            end = content_length - 1;
        }

        if (end >= content_length) {
            end = content_length;

        } else {
            end++;
        }

    found:

        if (start < end) {
            range = ngx_array_push(&ctx->ranges);
            if (range == NULL) {
                return NGX_ERROR;
            }

            range->start = start;
            range->end = end;
            range->fulfilled = 0;
            range->boundary_prepended = 0;
            range->boundary_appended = 0;

            if (size > NGX_MAX_OFF_T_VALUE - (end - start)) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            size += end - start;

            if (ranges-- == 0) {
                return NGX_DECLINED;
            }

        } else if (start == 0) {
            return NGX_DECLINED;
        }

        if (*p++ != ',') {
            break;
        }
    }

    if (ctx->ranges.nelts == 0) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (size > content_length) {
        return NGX_DECLINED;
    }

    if (ctx->ranges.nelts > 1) {
        r->ranges =  &ctx->ranges;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_range_singlepart_header(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx)
{
    ngx_table_elt_t   *content_range;
    ngx_http_range_t  *range;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    content_range = ngx_list_push(&r->headers_out.headers);
    if (content_range == NULL) {
        return NGX_ERROR;
    }

    if (r->headers_out.content_range) {
        r->headers_out.content_range->hash = 0;
    }

    r->headers_out.content_range = content_range;

    content_range->hash = 1;
    content_range->next = NULL;
    ngx_str_set(&content_range->key, "Content-Range");

    content_range->value.data = ngx_pnalloc(r->pool,
                                    sizeof("bytes -/") - 1 + 3 * NGX_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        content_range->hash = 0;
        r->headers_out.content_range = NULL;
        return NGX_ERROR;
    }

    /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

    range = ctx->ranges.elts;

    content_range->value.len = ngx_sprintf(content_range->value.data,
                                           "bytes %O-%O/%O",
                                           range->start, range->end - 1,
                                           r->headers_out.content_length_n)
                               - content_range->value.data;

    r->headers_out.content_length_n = range->end - range->start;
    r->headers_out.content_offset = range->start;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_range_multipart_header(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx)
{
    off_t               len;
    size_t              size;
    ngx_uint_t          i;
    ngx_http_range_t   *range;
    ngx_atomic_uint_t   boundary;

    size = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
           + sizeof(CRLF "Content-Type: ") - 1
           + r->headers_out.content_type.len
           + sizeof(CRLF "Content-Range: bytes ") - 1;

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        size += sizeof("; charset=") - 1 + r->headers_out.charset.len;
    }

    ctx->boundary_header.data = ngx_pnalloc(r->pool, size);
    if (ctx->boundary_header.data == NULL) {
        return NGX_ERROR;
    }

    boundary = ngx_next_temp_number(0);

    /*
     * The boundary header of the range:
     * CRLF
     * "--0123456789" CRLF
     * "Content-Type: image/jpeg" CRLF
     * "Content-Range: bytes "
     */

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V; charset=%V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type,
                                           &r->headers_out.charset)
                                   - ctx->boundary_header.data;

    } else if (r->headers_out.content_type.len) {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type)
                                   - ctx->boundary_header.data;

    } else {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Range: bytes ",
                                           boundary)
                                   - ctx->boundary_header.data;
    }

    r->headers_out.content_type.data =
        ngx_pnalloc(r->pool,
                    sizeof("Content-Type: multipart/byteranges; boundary=") - 1
                    + NGX_ATOMIC_T_LEN);

    if (r->headers_out.content_type.data == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_type_lowcase = NULL;

    /* "Content-Type: multipart/byteranges; boundary=0123456789" */

    r->headers_out.content_type.len =
                           ngx_sprintf(r->headers_out.content_type.data,
                                       "multipart/byteranges; boundary=%0muA",
                                       boundary)
                           - r->headers_out.content_type.data;

    r->headers_out.content_type_len = r->headers_out.content_type.len;

    r->headers_out.charset.len = 0;

    /* the size of the last boundary CRLF "--0123456789--" CRLF */

    len = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN + sizeof("--" CRLF) - 1;

    range = ctx->ranges.elts;
    for (i = 0; i < ctx->ranges.nelts; i++) {

        /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

        range[i].content_range.data =
                               ngx_pnalloc(r->pool, 3 * NGX_OFF_T_LEN + 2 + 4);

        if (range[i].content_range.data == NULL) {
            return NGX_ERROR;
        }

        range[i].content_range.len = ngx_sprintf(range[i].content_range.data,
                                               "%O-%O/%O" CRLF CRLF,
                                               range[i].start, range[i].end - 1,
                                               r->headers_out.content_length_n)
                                     - range[i].content_range.data;

        len += ctx->boundary_header.len + range[i].content_range.len
                                             + (range[i].end - range[i].start);
    }

    r->headers_out.content_length_n = len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    if (r->headers_out.content_range) {
        r->headers_out.content_range->hash = 0;
        r->headers_out.content_range = NULL;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_range_not_satisfiable(ngx_http_request_t *r)
{
    ngx_table_elt_t  *content_range;

    r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;

    content_range = ngx_list_push(&r->headers_out.headers);
    if (content_range == NULL) {
        return NGX_ERROR;
    }

    if (r->headers_out.content_range) {
        r->headers_out.content_range->hash = 0;
    }

    r->headers_out.content_range = content_range;

    content_range->hash = 1;
    content_range->next = NULL;
    ngx_str_set(&content_range->key, "Content-Range");

    content_range->value.data = ngx_pnalloc(r->pool,
                                       sizeof("bytes */") - 1 + NGX_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        content_range->hash = 0;
        r->headers_out.content_range = NULL;
        return NGX_ERROR;
    }

    content_range->value.len = ngx_sprintf(content_range->value.data,
                                           "bytes */%O",
                                           r->headers_out.content_length_n)
                               - content_range->value.data;

    ngx_http_clear_content_length(r);

    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
}


static ngx_int_t
ngx_http_range_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_range_filter_ctx_t  *ctx;
    ngx_int_t rc;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_range_body_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->ranges.nelts == 1) {
        return ngx_http_range_singlepart_body(r, ctx, in);
    }

    /*
     * multipart ranges are supported only if whole body is in a single buffer
     */

    if (ngx_buf_special(in->buf)) {
        return ngx_http_next_body_filter(r, in);
    }

    if (0 && ngx_http_range_test_overlapped(r, ctx, in) != NGX_OK) {
      return NGX_ERROR;
    }

   rc =  ngx_http_multirange_body(r, ctx, in);
   if (rc == NGX_DECLINED) {
        return ngx_http_range_multipart_body(r, ctx, in);
   } else {
       return rc;
   }
}


static ngx_int_t
ngx_http_range_test_overlapped(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
{
    off_t              start, last;
    ngx_buf_t         *buf;
    ngx_uint_t         i;
    ngx_http_range_t  *range;

    if (ctx->offset) {
        goto overlapped;
    }

    buf = in->buf;

    if (!buf->last_buf) {
        start = ctx->offset;
        last = ctx->offset + ngx_buf_size(buf);

        range = ctx->ranges.elts;
        for (i = 0; i < ctx->ranges.nelts; i++) {
            if (start > range[i].start || last < range[i].end) {
                goto overlapped;
            }
        }
    }

    ctx->offset = ngx_buf_size(buf);

    return NGX_OK;

overlapped:

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "range in overlapped buffers");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_range_singlepart_body(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
{
    off_t              start, last;
    ngx_int_t          rc;
    ngx_buf_t         *buf;
    ngx_chain_t       *out, *cl, *tl, **ll;
    ngx_http_range_t  *range;

    out = NULL;
    ll = &out;
    range = ctx->ranges.elts;

    for (cl = in; cl; cl = cl->next) {

        buf = cl->buf;

        start = ctx->offset;
        last = ctx->offset + ngx_buf_size(buf);

        ctx->offset = last;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http range body buf: %O-%O", start, last);

        if (ngx_buf_special(buf)) {

            if (range->end <= start) {
                continue;
            }

            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = buf;
            tl->next = NULL;

            *ll = tl;
            ll = &tl->next;

            continue;
        }

        if (range->end <= start || range->start >= last) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http range body skip");

            if (buf->in_file) {
                buf->file_pos = buf->file_last;
            }

            buf->pos = buf->last;
            buf->sync = 1;

            continue;
        }

        if (range->start > start) {

            if (buf->in_file) {
                buf->file_pos += range->start - start;
            }

            if (ngx_buf_in_memory(buf)) {
                buf->pos += (size_t) (range->start - start);
            }
        }

        if (range->end <= last) {

            if (buf->in_file) {
                buf->file_last -= last - range->end;
            }

            if (ngx_buf_in_memory(buf)) {
                buf->last -= (size_t) (last - range->end);
            }

            buf->last_buf = (r == r->main) ? 1 : 0;
            buf->last_in_chain = 1;

            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = buf;
            tl->next = NULL;

            *ll = tl;
            ll = &tl->next;

            continue;
        }

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        tl->buf = buf;
        tl->next = NULL;

        *ll = tl;
        ll = &tl->next;
    }

    rc = ngx_http_next_body_filter(r, out);

    while (out) {
        cl = out;
        out = out->next;
        ngx_free_chain(r->pool, cl);
    }

    return rc;
}


static ngx_int_t
ngx_http_range_multipart_body(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_buf_t         *b, *buf;
    ngx_uint_t         i;
    ngx_chain_t       *out, *hcl, *rcl, *dcl, **ll;
    ngx_http_range_t  *range;

    ll = &out;
    buf = in->buf;
    range = ctx->ranges.elts;

    for (i = 0; i < ctx->ranges.nelts; i++) {

        /*
         * The boundary header of the range:
         * CRLF
         * "--0123456789" CRLF
         * "Content-Type: image/jpeg" CRLF
         * "Content-Range: bytes "
         */

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = ctx->boundary_header.data;
        b->last = ctx->boundary_header.data + ctx->boundary_header.len;

        hcl = ngx_alloc_chain_link(r->pool);
        if (hcl == NULL) {
            return NGX_ERROR;
        }

        hcl->buf = b;


        /* "SSSS-EEEE/TTTT" CRLF CRLF */

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->temporary = 1;
        b->pos = range[i].content_range.data;
        b->last = range[i].content_range.data + range[i].content_range.len;

        rcl = ngx_alloc_chain_link(r->pool);
        if (rcl == NULL) {
            return NGX_ERROR;
        }

        rcl->buf = b;


        /* the range data */

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->in_file = buf->in_file;
        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->file = buf->file;

        if (buf->in_file) {
            b->file_pos = buf->file_pos + range[i].start;
            b->file_last = buf->file_pos + range[i].end;
        }

        if (ngx_buf_in_memory(buf)) {
            b->pos = buf->pos + (size_t) range[i].start;
            b->last = buf->pos + (size_t) range[i].end;
        }

        dcl = ngx_alloc_chain_link(r->pool);
        if (dcl == NULL) {
            return NGX_ERROR;
        }

        dcl->buf = b;

        *ll = hcl;
        hcl->next = rcl;
        rcl->next = dcl;
        ll = &dcl->next;
    }

    /* the last boundary CRLF "--0123456789--" CRLF  */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->temporary = 1;
    b->last_buf = 1;

    b->pos = ngx_pnalloc(r->pool, sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
                                  + sizeof("--" CRLF) - 1);
    if (b->pos == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->pos, ctx->boundary_header.data,
                         sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN);
    *b->last++ = '-'; *b->last++ = '-';
    *b->last++ = CR; *b->last++ = LF;

    hcl = ngx_alloc_chain_link(r->pool);
    if (hcl == NULL) {
        return NGX_ERROR;
    }

    hcl->buf = b;
    hcl->next = NULL;

    *ll = hcl;

    return ngx_http_next_body_filter(r, out);
}


static ngx_int_t
ngx_http_range_header_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_range_header_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_range_body_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_range_body_filter;

    return NGX_OK;
}

/*
 * I think I can get rid of all ngx_buf_in_memory() conditons
 * because I am interested in making multiranges work with slicing
 * and slicing is stricly a cache feature
 */
static ngx_int_t
ngx_http_multirange_body(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_chain_t              *out, *hcl, *rcl, *dcl, **ll;
    off_t                     start, last, bytes_lacking;
    ngx_http_range_t         *range, *last_range;
    ngx_http_slice_range_t   *slice_range;
    ngx_buf_t                *b, *buf;
    ngx_uint_t                i;
    ngx_int_t                 rc;

    if (!r->cache) {
        return NGX_DECLINED;
    }

    buf = in->buf;
    if (!buf->file) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_multirange_body() received non-file buf in->buf");
        r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    if (buf->temp_file) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "multirange: skipping temp cache file received\"%V\"",
                &buf->file->name);
        return NGX_OK;
    }

    rc = ngx_http_multirange_slice_range(r, &slice_range);
    if (rc != NGX_OK) {
        return rc;
    }

    ll = &out;
    range = ctx->ranges.elts;
    last_range = &range[ctx->ranges.nelts - 1];


    for (i = 0; i < ctx->ranges.nelts; i++) {

        bytes_lacking = ((range[i].end - range[i].start) - range[i].fulfilled);
        if (bytes_lacking == 0) {
            continue;
        }

        start = ctx->offset;
        /* multiple of slice size or 0
         * or, if MISS, the ammount of bytes fetched from upstream
         * in current event pipe loop; but I skip if temp_file
         * because I can't rely on this offset if I accept incomplete slices
         * and also skip slices when needed
         */
        last = ctx->offset + ngx_buf_size(buf);
        ctx->offset = last;
        /* Have to make sure I (need / don't need to) update ctx->offset when
         * move to next range;
         * And handle correctly the case where the current in buf can serve
         * several ranges, if I ever get that far.
         */


        if (range[i].boundary_prepended) {/*goto: the range data */} else {
            /*
             * The boundary header of the range:
             * CRLF
             * "--0123456789" CRLF
             * "Content-Type: image/jpeg" CRLF
             * "Content-Range: bytes "
             */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->memory = 1;
            b->pos = ctx->boundary_header.data;
            b->last = ctx->boundary_header.data + ctx->boundary_header.len;

            hcl = ngx_alloc_chain_link(r->pool);
            if (hcl == NULL) {
                return NGX_ERROR;
            }

            hcl->buf = b;


            /* "SSSS-EEEE/TTTT" CRLF CRLF */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->temporary = 1;
            b->pos = range[i].content_range.data;
            b->last = range[i].content_range.data + range[i].content_range.len;

            rcl = ngx_alloc_chain_link(r->pool);
            if (rcl == NULL) {
                return NGX_ERROR;
            }

            rcl->buf = b;
        }

        /* the range data */
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        /* skip this slice, 1st slice opened by default
         * or MISS and this slice is slowly being appended to
         * (but now I skip temp_files, wait for slice to be full)
         */
        if ( /*range[i].fulfilled == 0 && */ /* this one may be superfluous */
                (range[i].end < slice_range->start ||
                 range[i].start > slice_range->end)) /* was >= and caused bug */
        {
            /* 99% certain but leaving error just in case */
            if (slice_range->start || range[i].fulfilled) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "multirange skip slice %O-%O ; range:%O-%O",
                    slice_range->start, slice_range->end,
                    range[i].start, range[i].end);
            }

            if (range[i].boundary_prepended) {
                dcl = ngx_alloc_chain_link(r->pool);
                if (dcl == NULL) {
                    return NGX_ERROR;
                }
                b->sync = 1;
                dcl->buf = b;
                dcl->next = NULL;
                *ll = dcl;
                ll = &dcl->next;
                break;
            }

            *ll = hcl;
            hcl->next = rcl;
            rcl->next = NULL;
            ll = &rcl->next;
            range[i].boundary_prepended = 1;
            break;
        }

        b->in_file = buf->in_file;
        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->file = buf->file;

        if (range[i].start > start) {
            /* works if slices up to the slice containing the start of this range were skipped */
            b->file_pos = buf->file_pos + (range[i].start - start);
        } else {
            b->file_pos = buf->file_pos;
        }

        if (bytes_lacking <= (buf->file_last - b->file_pos)) {
            b->file_last = b->file_pos + bytes_lacking;
        } else {
            b->file_last = buf->file_last;
        }

        dcl = ngx_alloc_chain_link(r->pool);
        if (dcl == NULL) {
            return NGX_ERROR;
        }

        dcl->buf = b;
        dcl->next = NULL;

        if (!range[i].boundary_prepended) {
            *ll = hcl;
            hcl->next = rcl;
            rcl->next = dcl;
            ll = &dcl->next;
            range[i].boundary_prepended = 1;
        } else {
            *ll = dcl;
            ll = &dcl->next;
        }

        if (b->file_pos < buf->file_pos) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "multirange: b->file_pos(%O) < buf->file_pos(%O)",
                    b->file_pos, buf->file_pos);
            r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }

        range[i].fulfilled += (b->file_last - b->file_pos);
        break;
    }

    /*
     * what if only your last range can be fulfilled from first slice?
     * Don't get clever and work with one range at a time for now.
     * Even if it means opening the same slice multiple times.
     * Because the client is dumb as a brick and requested overlapping ranges.
     */
    if (last_range->fulfilled == (last_range->end - last_range->start)) {
        /* the last boundary CRLF "--0123456789--" CRLF  */

        if (last_range->boundary_appended) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "multirange: appending excess boundary to range \'%*s\'",
                    last_range->content_range.len-4,
                    last_range->content_range.data);
            r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->temporary = 1;
        b->last_buf = 1;

        b->pos = ngx_pnalloc(r->pool, sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
                                      + sizeof("--" CRLF) - 1);
        if (b->pos == NULL) {
            return NGX_ERROR;
        }

        b->last = ngx_cpymem(b->pos, ctx->boundary_header.data,
                             sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN);
        *b->last++ = '-'; *b->last++ = '-';
        *b->last++ = CR; *b->last++ = LF;

        hcl = ngx_alloc_chain_link(r->pool);
        if (hcl == NULL) {
            return NGX_ERROR;
        }

        hcl->buf = b;
        hcl->next = NULL;

        *ll = hcl;
        last_range->boundary_appended = 1;
    }

    return ngx_http_next_body_filter(r, out);
}

static ngx_int_t
ngx_http_multirange_header(ngx_http_request_t *r,
    ngx_http_range_filter_ctx_t *ctx)
{
    off_t               len;
    size_t              size;
    ngx_uint_t          i;
    ngx_http_range_t   *range;
    ngx_atomic_uint_t   boundary;

    ngx_http_range_filter_ctx_t  *mctx;

    if (r != r->main) {
        mctx = ngx_http_get_module_ctx(r->main,
                                       ngx_http_range_body_filter_module);
        if (mctx) {
            ctx->boundary_header.len = mctx->boundary_header.len;
            ctx->boundary_header.data = mctx->boundary_header.data;
        }

        r->headers_out.content_offset = r->main->headers_out.content_offset;
        r->headers_out.content_type.data = r->main->headers_out.content_type.data;
        r->headers_out.content_type.len = r->main->headers_out.content_type.len;
        r->headers_out.content_type_len = r->headers_out.content_type.len;
        r->headers_out.content_offset = r->main->headers_out.content_offset; /* TODO */
        r->headers_out.content_length_n = r->main->headers_out.content_length_n;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }
        if (r->headers_out.content_range) {
            r->headers_out.content_range->hash = 0;
            r->headers_out.content_range = NULL;
        }

        return ngx_http_next_header_filter(r);
    }


    size = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
           + sizeof(CRLF "Content-Type: ") - 1
           + r->headers_out.content_type.len
           + sizeof(CRLF "Content-Range: bytes ") - 1;

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        size += sizeof("; charset=") - 1 + r->headers_out.charset.len;
    }

    ctx->boundary_header.data = ngx_pnalloc(r->pool, size);
    if (ctx->boundary_header.data == NULL) {
        return NGX_ERROR;
    }

    boundary = ngx_next_temp_number(0);

    /*
     * The boundary header of the range:
     * CRLF
     * "--0123456789" CRLF
     * "Content-Type: image/jpeg" CRLF
     * "Content-Range: bytes "
     */

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V; charset=%V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type,
                                           &r->headers_out.charset)
                                   - ctx->boundary_header.data;

    } else if (r->headers_out.content_type.len) {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type)
                                   - ctx->boundary_header.data;

    } else {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Range: bytes ",
                                           boundary)
                                   - ctx->boundary_header.data;
    }

    r->headers_out.content_type.data =
        ngx_pnalloc(r->pool,
                    sizeof("Content-Type: multipart/byteranges; boundary=") - 1
                    + NGX_ATOMIC_T_LEN);

    if (r->headers_out.content_type.data == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_type_lowcase = NULL;

    /* "Content-Type: multipart/byteranges; boundary=0123456789" */

    r->headers_out.content_type.len =
                           ngx_sprintf(r->headers_out.content_type.data,
                                       "multipart/byteranges; boundary=%0muA",
                                       boundary)
                           - r->headers_out.content_type.data;

    r->headers_out.content_type_len = r->headers_out.content_type.len;

    r->headers_out.charset.len = 0;

    /* the size of the last boundary CRLF "--0123456789--" CRLF */

    len = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN + sizeof("--" CRLF) - 1;

    range = ctx->ranges.elts;
    r->headers_out.content_offset = range[0].start;
    /*
     * if/when you decide to be optimal and fulfill ranges
     * out of the file you have open
     * you can set it to the lowest range start
     */
    for (i = 0; i < ctx->ranges.nelts; i++) {

        /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

        range[i].content_range.data =
                               ngx_pnalloc(r->pool, 3 * NGX_OFF_T_LEN + 2 + 4);

        if (range[i].content_range.data == NULL) {
            return NGX_ERROR;
        }

        range[i].content_range.len = ngx_sprintf(range[i].content_range.data,
                                               "%O-%O/%O" CRLF CRLF,
                                               range[i].start, range[i].end - 1,
                                               r->headers_out.content_length_n)
                                     - range[i].content_range.data;

        len += ctx->boundary_header.len + range[i].content_range.len
                                             + (range[i].end - range[i].start);
    }

    r->headers_out.content_length_n = len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    if (r->headers_out.content_range) {
        r->headers_out.content_range->hash = 0;
        r->headers_out.content_range = NULL;
    }

    return ngx_http_next_header_filter(r);
}

/*
 * Have to check the current cache key.
 * Because making ngx_http_slice_get_start() handle ',' in range breaks the case
 * when the sum of ranges is greater than file size and we should just serve 200.
 * So, I will let ngx_http_slice_get_start() always give me the first slice
 * and skip it if it doesn't satisfy my first range.
 */

static ngx_int_t
ngx_http_multirange_slice_range(ngx_http_request_t *r,
        ngx_http_slice_range_t **slice_range)
{
    off_t                    cache_length;
    ngx_str_t                proxy_key;
    ngx_http_slice_range_t  *sr;
    u_char                  *p;

    /*
     * This string is generated in slice filter module, not provided by users
     * so I don't need to be too paranoid about it.
     * ((ngx_str_t *)r->cache->keys.elts)[0] ;ex: "/f1024|bytes=500-999"
     */

    *slice_range = ngx_pcalloc(r->pool, sizeof(ngx_http_slice_range_t));
    if (*slice_range == NULL) {
        return NGX_ERROR;
    }
    sr = *slice_range;

    cache_length = r->cache->length - r->cache->body_start - 1;

    proxy_key = ((ngx_str_t *) r->cache->keys.elts)[0];
    p = (u_char *) ngx_strstr(proxy_key.data, "bytes=");

    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "multirange: slice range not in cache key: \"%V\"", &proxy_key);
        return NGX_DECLINED;
    }

    p = &p[sizeof("bytes=") - 1];

    while (*p >= '0' && *p <= '9') {
        sr->start = sr->start * 10 + (*p++ - '0');
    }

    p++; /* skip the '-' */

    while (*p >= '0' && *p <= '9') {
        sr->end = sr->end * 10 + (*p++ - '0');

        if ((sr->end > sr->start) && (sr->end - sr->start) >= cache_length) {
            break;
        }
    }

    /*
     * I'm assuming $slice_range is the last var in the cache key here
     * it still works so long as the next variable after it is not numeric
     * $request_uri|$slice_range|$pid works
     * $request_uri|$slice_range$pid breaks it
     * EDIT: the cache_length condition saves that case
     */

    if ((sr->end - sr->start) > cache_length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "multirange: slice range:%O-%O(%O) > cache length:%O",
                sr->start, sr->end, sr->end - sr->start, cache_length);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "multirange: slice_range->start: %O | slice_range->end %O",
            sr->start, sr->end);

    return NGX_OK;
}

