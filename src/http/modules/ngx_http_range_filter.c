
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


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
 * the mutlipart format:
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
    ngx_str_t  boundary_header;
} ngx_http_range_filter_ctx_t;


static ngx_int_t ngx_http_range_header_filter_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_range_body_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_range_header_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_range_header_filter_module = {
    NGX_MODULE,
    &ngx_http_range_header_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_range_header_filter_init,     /* init module */
    NULL                                   /* init child */
};


static ngx_http_module_t  ngx_http_range_body_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_range_body_filter_module = {
    NGX_MODULE,
    &ngx_http_range_body_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_range_body_filter_init,       /* init module */
    NULL                                   /* init child */
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t ngx_http_range_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_uint_t                    boundary, suffix, i;
    u_char                       *p;
    size_t                        len;
    off_t                         start, end;
    ngx_http_range_t             *range;
    ngx_http_range_filter_ctx_t  *ctx;

    if (r->http_version < NGX_HTTP_VERSION_10
        || r->headers_out.status != NGX_HTTP_OK
        || r->headers_out.content_length_n == -1
        || !r->filter_allow_ranges)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data, "bytes=", 6) != 0)
    {

        r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.accept_ranges == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.accept_ranges->key.len = sizeof("Accept-Ranges") - 1;
        r->headers_out.accept_ranges->key.data = (u_char *) "Accept-Ranges";
        r->headers_out.accept_ranges->value.len = sizeof("bytes") - 1;
        r->headers_out.accept_ranges->value.data = (u_char *) "bytes";

        return ngx_http_next_header_filter(r);
    }

    ngx_init_array(r->headers_out.ranges, r->pool, 5, sizeof(ngx_http_range_t),
                   NGX_ERROR);

    rc = 0;
    range = NULL;
    p = r->headers_in.range->value.data + 6;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;

        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
                break;
            }

            while (*p >= '0' && *p <= '9') {
                start = start * 10 + *p++ - '0';
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
                break;
            }

            if (start >= r->headers_out.content_length_n) {
                rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
                break;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                ngx_test_null(range, ngx_push_array(&r->headers_out.ranges),
                              NGX_ERROR);
                range->start = start;
                range->end = r->headers_out.content_length_n;

                if (*p++ != ',') {
                    break;
                }

                continue;
            }

        } else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            break;
        }

        while (*p >= '0' && *p <= '9') {
            end = end * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            break;
        }

        if (suffix) {
           start = r->headers_out.content_length_n - end;
           end = r->headers_out.content_length_n - 1;
        }

        if (start > end) {
            rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            break;
        }

        ngx_test_null(range, ngx_push_array(&r->headers_out.ranges), NGX_ERROR);
        range->start = start;

        if (end >= r->headers_out.content_length_n) {
            /*
             * Download Accelerator sends the last byte position
             * that equals to the file length
             */
            range->end = r->headers_out.content_length_n;

        } else {
            range->end = end + 1;
        }

        if (*p++ != ',') {
            break;
        }
    }

    if (rc) {

        /* rc == NGX_HTTP_RANGE_NOT_SATISFIABLE */

        r->headers_out.status = rc;
        r->headers_out.ranges.nelts = 0;

        r->headers_out.content_range = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.content_range == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.content_range->key.len = sizeof("Content-Range") - 1;
        r->headers_out.content_range->key.data = (u_char *) "Content-Range";

        r->headers_out.content_range->value.data =
                                               ngx_palloc(r->pool, 8 + 20 + 1);
        if (r->headers_out.content_range->value.data == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.content_range->value.len =
                ngx_snprintf((char *) r->headers_out.content_range->value.data,
                             8 + 20 + 1, "bytes */" OFF_T_FMT,
                             r->headers_out.content_length_n);

        r->headers_out.content_length_n = -1;
        if (r->headers_out.content_length) {
            r->headers_out.content_length->key.len = 0;
            r->headers_out.content_length = NULL;
        }

        return rc;

    } else {
        r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;

        if (r->headers_out.ranges.nelts == 1) {

            r->headers_out.content_range =
                                        ngx_list_push(&r->headers_out.headers);
            if (r->headers_out.content_range == NULL) {
                return NGX_ERROR;
            }

            r->headers_out.content_range->key.len = sizeof("Content-Range") - 1;
            r->headers_out.content_range->key.data = (u_char *) "Content-Range";

            ngx_test_null(r->headers_out.content_range->value.data,
                          ngx_palloc(r->pool, 6 + 20 + 1 + 20 + 1 + 20 + 1),
                          NGX_ERROR);

            /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

            r->headers_out.content_range->value.len =
                   ngx_snprintf((char *)
                                r->headers_out.content_range->value.data,
                                6 + 20 + 1 + 20 + 1 + 20 + 1,
                                "bytes " OFF_T_FMT "-" OFF_T_FMT "/" OFF_T_FMT,
                                range->start, range->end - 1,
                                r->headers_out.content_length_n);

            r->headers_out.content_length_n = range->end - range->start;

        } else {

#if 0
            /* TODO: what if no content_type ?? */

            if (!(r->headers_out.content_type =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
            {
                return NGX_ERROR;
            }
#endif

            ngx_http_create_ctx(r, ctx, ngx_http_range_body_filter_module,
                                sizeof(ngx_http_range_filter_ctx_t), NGX_ERROR);

            len = 4 + 10 + 2 + 14 + r->headers_out.content_type->value.len
                                  + 2 + 21 + 1;

            if (r->headers_out.charset.len) {
                len += 10 + r->headers_out.charset.len;
            }

            ngx_test_null(ctx->boundary_header.data, ngx_palloc(r->pool, len),
                          NGX_ERROR);

            boundary = ngx_next_temp_number(0);

            /*
             * The boundary header of the range:
             * CRLF
             * "--0123456789" CRLF
             * "Content-Type: image/jpeg" CRLF
             * "Content-Range: bytes "
             */

            if (r->headers_out.charset.len) {
                ctx->boundary_header.len =
                         ngx_snprintf((char *) ctx->boundary_header.data, len,
                                      CRLF "--%010" NGX_UINT_T_FMT CRLF
                                      "Content-Type: %s; charset=%s" CRLF
                                      "Content-Range: bytes ",
                                      boundary,
                                      r->headers_out.content_type->value.data,
                                      r->headers_out.charset.data);

                r->headers_out.charset.len = 0;

            } else {
                ctx->boundary_header.len =
                         ngx_snprintf((char *) ctx->boundary_header.data, len,
                                      CRLF "--%010" NGX_UINT_T_FMT CRLF
                                      "Content-Type: %s" CRLF
                                      "Content-Range: bytes ",
                                      boundary,
                                      r->headers_out.content_type->value.data);
            }

            ngx_test_null(r->headers_out.content_type->value.data,
                          ngx_palloc(r->pool, 31 + 10 + 1),
                          NGX_ERROR);

            /* "Content-Type: multipart/byteranges; boundary=0123456789" */

            r->headers_out.content_type->value.len =
                      ngx_snprintf((char *)
                                   r->headers_out.content_type->value.data,
                                   31 + 10 + 1,
                                   "multipart/byteranges; boundary=%010"
                                   NGX_UINT_T_FMT,
                                   boundary);

            /* the size of the last boundary CRLF "--0123456789--" CRLF */
            len = 4 + 10 + 4;

            range = r->headers_out.ranges.elts;
            for (i = 0; i < r->headers_out.ranges.nelts; i++) {
                ngx_test_null(range[i].content_range.data,
                              ngx_palloc(r->pool, 20 + 1 + 20 + 1 + 20 + 5),
                              NGX_ERROR);

                /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

                range[i].content_range.len =
                  ngx_snprintf((char *) range[i].content_range.data,
                               20 + 1 + 20 + 1 + 20 + 5,
                               OFF_T_FMT "-" OFF_T_FMT "/" OFF_T_FMT CRLF CRLF,
                               range[i].start, range[i].end - 1,
                               r->headers_out.content_length_n);

                len += ctx->boundary_header.len + range[i].content_range.len
                                    + (size_t) (range[i].end - range[i].start);
            }

            r->headers_out.content_length_n = len;
            r->headers_out.content_length = NULL;
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_range_body_filter(ngx_http_request_t *r,
                                            ngx_chain_t *in)
{
    ngx_uint_t                    i;
    ngx_buf_t                    *b;
    ngx_chain_t                  *out, *hcl, *rcl, *dcl, **ll;
    ngx_http_range_t             *range;
    ngx_http_range_filter_ctx_t  *ctx;

    if (r->headers_out.ranges.nelts == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    /*
     * the optimized version for the static files only
     * that are passed in the single file buf
     */

    if (in && in->buf->in_file && in->buf->last_buf) {
        range = r->headers_out.ranges.elts;

        if (r->headers_out.ranges.nelts == 1) {
            in->buf->file_pos = range->start;
            in->buf->file_last = range->end;

            return ngx_http_next_body_filter(r, in);
        }

        ctx = ngx_http_get_module_ctx(r, ngx_http_range_body_filter_module);
        ll = &out;

        for (i = 0; i < r->headers_out.ranges.nelts; i++) {

            /*
             * The boundary header of the range:
             * CRLF
             * "--0123456789" CRLF
             * "Content-Type: image/jpeg" CRLF
             * "Content-Range: bytes "
             */

            ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
            b->memory = 1;
            b->pos = ctx->boundary_header.data;
            b->last = ctx->boundary_header.data + ctx->boundary_header.len;

            ngx_test_null(hcl, ngx_alloc_chain_link(r->pool), NGX_ERROR);
            hcl->buf = b;

            /* "SSSS-EEEE/TTTT" CRLF CRLF */

            ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
            b->temporary = 1;
            b->pos = range[i].content_range.data;
            b->last = range[i].content_range.data + range[i].content_range.len;

            ngx_test_null(rcl, ngx_alloc_chain_link(r->pool), NGX_ERROR);
            rcl->buf = b;

            /* the range data */

            ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
            b->in_file = 1;
            b->file_pos = range[i].start;
            b->file_last = range[i].end;
            b->file = in->buf->file;

            ngx_alloc_link_and_set_buf(dcl, b, r->pool, NGX_ERROR);

            *ll = hcl;
            hcl->next = rcl;
            rcl->next = dcl;
            ll = &dcl->next;
        }

        /* the last boundary CRLF "--0123456789--" CRLF  */

        ngx_test_null(b, ngx_calloc_buf(r->pool), NGX_ERROR);
        b->temporary = 1;
        b->last_buf = 1;
        ngx_test_null(b->pos, ngx_palloc(r->pool, 4 + 10 + 4), NGX_ERROR);
        b->last = ngx_cpymem(b->pos, ctx->boundary_header.data, 4 + 10);
        *b->last++ = '-'; *b->last++ = '-';
        *b->last++ = CR; *b->last++ = LF;

        ngx_alloc_link_and_set_buf(hcl, b, r->pool, NGX_ERROR);
        *ll = hcl;

        return ngx_http_next_body_filter(r, out);
    }

    /* TODO: alert */

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t ngx_http_range_header_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_range_header_filter;

    return NGX_OK;
}


static ngx_int_t ngx_http_range_body_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_range_body_filter;

    return NGX_OK;
}
