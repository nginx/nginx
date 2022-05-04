
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    size_t               size;
} ngx_http_slice_loc_conf_t;


typedef struct {
    off_t                start;
    off_t                end;
    ngx_str_t            range;
    ngx_str_t            etag;
    unsigned             last:1;
    unsigned             active:1;
    ngx_http_request_t  *sr;
} ngx_http_slice_ctx_t;


typedef struct {
    off_t                start;
    off_t                end;
    off_t                complete_length;
} ngx_http_slice_content_range_t;


static ngx_int_t ngx_http_slice_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_slice_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_slice_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_content_range_t *cr);
static ngx_int_t ngx_http_slice_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static off_t ngx_http_slice_get_start(ngx_http_request_t *r);
static void *ngx_http_slice_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_slice_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_slice_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_slice_filter_commands[] = {

    { ngx_string("slice"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_loc_conf_t, size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_slice_filter_module_ctx = {
    ngx_http_slice_add_variables,          /* preconfiguration */
    ngx_http_slice_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_slice_create_loc_conf,        /* create location configuration */
    ngx_http_slice_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_slice_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_slice_filter_module_ctx,     /* module context */
    ngx_http_slice_filter_commands,        /* module directives */
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


static ngx_str_t  ngx_http_slice_range_name = ngx_string("slice_range");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_slice_header_filter(ngx_http_request_t *r)
{
    off_t                            end;
    ngx_int_t                        rc;
    ngx_table_elt_t                 *h;
    ngx_http_slice_ctx_t            *ctx;
    ngx_http_slice_loc_conf_t       *slcf;
    ngx_http_slice_content_range_t   cr;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT) {
        if (r == r->main) {
            ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
            return ngx_http_next_header_filter(r);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || ngx_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "etag mismatch in slice response");
            return NGX_ERROR;
        }
    }

    if (h) {
        ctx->etag = h->value;
    }

    if (ngx_http_slice_parse_content_range(r, &cr) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid range in slice response");
        return NGX_ERROR;
    }

    if (cr.complete_length == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no complete length in slice response");
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice response range: %O-%O/%O",
                   cr.start, cr.end, cr.complete_length);

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

    end = ngx_min(cr.start + (off_t) slcf->size, cr.complete_length);

    if (cr.start != ctx->start || cr.end != end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected range in slice response: %O-%O",
                      cr.start, cr.end);
        return NGX_ERROR;
    }

    ctx->start = end;
    ctx->active = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;
    r->headers_out.content_range->hash = 0;
    r->headers_out.content_range = NULL;

    if (r->headers_out.accept_ranges) {
        r->headers_out.accept_ranges->hash = 0;
        r->headers_out.accept_ranges = NULL;
    }

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    rc = ngx_http_next_header_filter(r);

    if (r != r->main) {
        return rc;
    }

    r->preserve_body = 1;

    if (r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT) {
        if (ctx->start + (off_t) slcf->size <= r->headers_out.content_offset) {
            ctx->start = slcf->size
                         * (r->headers_out.content_offset / slcf->size);
        }

        ctx->end = r->headers_out.content_offset
                   + r->headers_out.content_length_n;

    } else {
        ctx->end = cr.complete_length;
    }

    return rc;
}


static ngx_int_t
ngx_http_slice_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                   rc;
    ngx_chain_t                *cl;
    ngx_http_slice_ctx_t       *ctx;
    ngx_http_slice_loc_conf_t  *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);

    if (ctx == NULL || r != r->main) {
        return ngx_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !ctx->last) {
        return rc;
    }

    if (ctx->sr && !ctx->sr->done) {
        return rc;
    }

    if (!ctx->active) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "missing slice response");
        return NGX_ERROR;
    }

    if (ctx->start >= ctx->end) {
        ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
        ngx_http_send_special(r, NGX_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    if (ngx_http_subrequest(r, &r->uri, &r->args, &ctx->sr, NULL,
                            NGX_HTTP_SUBREQUEST_CLONE)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(ctx->sr, ctx, ngx_http_slice_filter_module);

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

    ctx->range.len = ngx_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start,
                                 ctx->start + (off_t) slcf->size - 1)
                     - ctx->range.data;

    ctx->active = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


static ngx_int_t
ngx_http_slice_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    h = r->headers_out.content_range;

    if (h == NULL
        || h->value.len < 7
        || ngx_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return NGX_ERROR;
    }

    p = h->value.data + 6;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        start = start * 10 + (*p++ - '0');
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        end = end * 10 + (*p++ - '0');
    }

    end++;

    while (*p == ' ') { p++; }

    if (*p++ != '/') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return NGX_ERROR;
            }

            complete_length = complete_length * 10 + (*p++ - '0');
        }

    } else {
        complete_length = -1;
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NGX_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_http_slice_ctx_t       *ctx;
    ngx_http_slice_loc_conf_t  *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);

    if (ctx == NULL) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return NGX_OK;
        }

        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_slice_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_slice_filter_module);

        p = ngx_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ctx->start = slcf->size * (ngx_http_slice_get_start(r) / slcf->size);

        ctx->range.data = p;
        ctx->range.len = ngx_sprintf(p, "bytes=%O-%O", ctx->start,
                                     ctx->start + (off_t) slcf->size - 1)
                         - p;
    }

    v->data = ctx->range.data;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;
    v->len = ctx->range.len;

    return NGX_OK;
}


static off_t
ngx_http_slice_get_start(ngx_http_request_t *r)
{
    off_t             start, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    if (r->headers_in.if_range) {
        return 0;
    }

    h = r->headers_in.range;

    if (h == NULL
        || h->value.len < 7
        || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return 0;
    }

    p = h->value.data + 6;

    if (ngx_strchr(p, ',')) {
        return 0;
    }

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return 0;
    }

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return 0;
        }

        start = start * 10 + (*p++ - '0');
    }

    return start;
}


static void *
ngx_http_slice_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_slice_loc_conf_t  *slcf;

    slcf = ngx_palloc(cf->pool, sizeof(ngx_http_slice_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = NGX_CONF_UNSET_SIZE;

    return slcf;
}


static char *
ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_slice_loc_conf_t *prev = parent;
    ngx_http_slice_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->size, prev->size, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_slice_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_slice_range_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_slice_range_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_slice_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_slice_body_filter;

    return NGX_OK;
}
