
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


static int ngx_http_range_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_range_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_range_filter_module = {
    NGX_MODULE,
    &ngx_http_range_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_range_filter_init,            /* init module */
    NULL                                   /* init child */
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static int ngx_http_range_header_filter(ngx_http_request_t *r)
{
    int                           rc, boundary, len, i;
    char                         *p;
    off_t                         start, end;
    ngx_http_range_t             *range;
    ngx_http_range_filter_ctx_t  *ctx;

    if (r->http_version < NGX_HTTP_VERSION_10
        || r->headers_out.status != NGX_HTTP_OK
        || r->headers_out.content_length_n == -1

        /* STUB: we currently support ranges for file hunks only */
        || !r->sendfile
        || r->filter & NGX_HTTP_FILTER_NEED_IN_MEMORY)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data, "bytes=", 6) != 0)
    {
        ngx_test_null(r->headers_out.accept_ranges,
                      ngx_push_table(r->headers_out.headers),
                      NGX_ERROR);

        r->headers_out.accept_ranges->key.len = sizeof("Accept-Ranges") - 1;
        r->headers_out.accept_ranges->key.data = "Accept-Ranges";
        r->headers_out.accept_ranges->value.len = sizeof("bytes") - 1;
        r->headers_out.accept_ranges->value.data = "bytes";

        return ngx_http_next_header_filter(r);
    }

    ngx_init_array(r->headers_out.ranges, r->pool, 5, sizeof(ngx_http_range_t),
                   NGX_ERROR);

    rc = 0;
    range = NULL;
    p = r->headers_in.range->value.data + 6;

    for ( ;; ) {
        start = end = 0;

        while (*p == ' ') { p++; }

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

            if (*p++ == ',') {
                continue;
            }

            break;
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

        if (end >= r->headers_out.content_length_n || start >= end) {
            rc = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            break;
        }

        ngx_test_null(range, ngx_push_array(&r->headers_out.ranges), NGX_ERROR);
        range->start = start;
        range->end = end + 1;

        if (*p++ == ',') {
            continue;
        }

        break;
    }

    if (rc) {

        /* rc == NGX_HTTP_RANGE_NOT_SATISFIABLE */

        r->headers_out.status = rc;
        r->headers_out.ranges.nelts = 0;

        ngx_test_null(r->headers_out.content_range,
                      ngx_push_table(r->headers_out.headers),
                      NGX_ERROR);

        ngx_test_null(r->headers_out.content_range->value.data,
                      ngx_palloc(r->pool, 8 + 20 + 1),
                      NGX_ERROR);

        r->headers_out.content_range->value.len =
                        ngx_snprintf(r->headers_out.content_range->value.data,
                                     8 + 20 + 1, "bytes */" OFF_FMT,
                                     r->headers_out.content_length_n);

        r->headers_out.content_length_n = -1;
        r->headers_out.content_length = NULL;

        return rc;

    } else {
        r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;

        if (r->headers_out.ranges.nelts == 1) {
            ngx_test_null(r->headers_out.content_range,
                          ngx_push_table(r->headers_out.headers),
                          NGX_ERROR);

            ngx_test_null(r->headers_out.content_range->value.data,
                          ngx_palloc(r->pool, 6 + 20 + 1 + 20 + 1 + 20 + 1),
                          NGX_ERROR);

            /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

            r->headers_out.content_range->value.len =
                         ngx_snprintf(r->headers_out.content_range->value.data,
                                      6 + 20 + 1 + 20 + 1 + 20 + 1,
                                      "bytes " OFF_FMT "-" OFF_FMT "/" OFF_FMT,
                                      range->start, range->end - 1,
                                      r->headers_out.content_length_n);

            r->headers_out.content_length_n = range->end - range->start;

        } else {

#if 0
            /* TODO: what if no content_type ?? */
            ngx_test_null(r->headers_out.content_type,
                          ngx_push_table(r->headers_out.headers),
                          NGX_ERROR);
#endif

            ngx_http_create_ctx(r, ctx, ngx_http_range_filter_module,
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
                         ngx_snprintf(ctx->boundary_header.data, len,
                                      CRLF "--%010u" CRLF
                                      "Content-Type: %s; charset=%s" CRLF
                                      "Content-Range: bytes ",
                                      boundary,
                                      r->headers_out.content_type->value.data,
                                      r->headers_out.charset.data);

                r->headers_out.charset.len = 0;

            } else {
                ctx->boundary_header.len =
                         ngx_snprintf(ctx->boundary_header.data, len,
                                      CRLF "--%010u" CRLF
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
                      ngx_snprintf(r->headers_out.content_type->value.data,
                                   31 + 10 + 1,
                                   "multipart/byteranges; boundary=%010u",
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
                        ngx_snprintf(range[i].content_range.data,
                                     20 + 1 + 20 + 1 + 20 + 5,
                                     OFF_FMT "-" OFF_FMT "/" OFF_FMT CRLF CRLF,
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


static int ngx_http_range_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                           i;
    ngx_hunk_t                   *h;
    ngx_chain_t                  *out, *hcl, *rcl, *dcl, **ll;
    ngx_http_range_t             *range;
    ngx_http_range_filter_ctx_t  *ctx;

    if (r->headers_out.ranges.nelts == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    /*
     * the optimized version for the static files only
     * that are passed in the single file hunk
     */

    if (in
        && in->hunk->type & NGX_HUNK_FILE
        && in->hunk->type & NGX_HUNK_LAST)
    {
        range = r->headers_out.ranges.elts;

        if (r->headers_out.ranges.nelts == 1) {
            in->hunk->file_pos = range->start;
            in->hunk->file_last = range->end;

            return ngx_http_next_body_filter(r, in);
        }

        ctx = ngx_http_get_module_ctx(r, ngx_http_range_filter_module);
        ll = &out;

        for (i = 0; i < r->headers_out.ranges.nelts; i++) {

            /*
             * The boundary header of the range:
             * CRLF
             * "--0123456789" CRLF
             * "Content-Type: image/jpeg" CRLF
             * "Content-Range: bytes "
             */

            ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
            h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY;
            h->pos = ctx->boundary_header.data;
            h->last = ctx->boundary_header.data + ctx->boundary_header.len;

            ngx_test_null(hcl, ngx_alloc_chain_link(r->pool), NGX_ERROR);
            hcl->hunk = h;

            /* "SSSS-EEEE/TTTT" CRLF CRLF */

            ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
            h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
            h->pos = range[i].content_range.data;
            h->last = range[i].content_range.data + range[i].content_range.len;

            ngx_test_null(rcl, ngx_alloc_chain_link(r->pool), NGX_ERROR);
            rcl->hunk = h;

            /* the range data */

            ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
            h->type = NGX_HUNK_FILE;
            h->file_pos = range[i].start;
            h->file_last = range[i].end;
            h->file = in->hunk->file;

            ngx_alloc_link_and_set_hunk(dcl, h, r->pool, NGX_ERROR);

            *ll = hcl;
            hcl->next = rcl;
            rcl->next = dcl;
            ll = &dcl->next;
        }

        /* the last boundary CRLF "--0123456789--" CRLF  */

        ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP|NGX_HUNK_LAST;
        ngx_test_null(h->pos, ngx_palloc(r->pool, 4 + 10 + 4), NGX_ERROR);
        h->last = ngx_cpymem(h->pos, ctx->boundary_header.data, 4 + 10);
        *h->last++ = '-'; *h->last++ = '-';
        *h->last++ = CR; *h->last++ = LF;

        ngx_alloc_link_and_set_hunk(hcl, h, r->pool, NGX_ERROR);
        *ll = hcl;

        return ngx_http_next_body_filter(r, out);
    }

    /* TODO: several incoming hunks of proxied responses
             and memory hunks on platforms that have no sendfile() */

    return ngx_http_next_body_filter(r, in);
}


static int ngx_http_range_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_range_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_range_body_filter;

    return NGX_OK;
}
