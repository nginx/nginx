
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_test_precondition(ngx_http_request_t *r);
static ngx_int_t ngx_http_test_not_modified(ngx_http_request_t *r);
static ngx_int_t ngx_http_not_modified_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_not_modified_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_not_modified_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_not_modified_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_not_modified_filter_module_ctx, /* module context */
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


static ngx_int_t
ngx_http_not_modified_header_filter(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK
        || r != r->main
        || r->headers_out.last_modified_time == -1)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_in.if_unmodified_since) {
        return ngx_http_test_precondition(r);
    }

    if (r->headers_in.if_modified_since) {
        return ngx_http_test_not_modified(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_test_precondition(ngx_http_request_t *r)
{
    time_t  iums;

    iums = ngx_http_parse_time(r->headers_in.if_unmodified_since->value.data,
                               r->headers_in.if_unmodified_since->value.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http iums:%d lm:%d", iums, r->headers_out.last_modified_time);

    if (iums >= r->headers_out.last_modified_time) {
        return ngx_http_next_header_filter(r);
    }

    return ngx_http_filter_finalize_request(r, NULL,
                                            NGX_HTTP_PRECONDITION_FAILED);
}


static ngx_int_t
ngx_http_test_not_modified(ngx_http_request_t *r)
{
    time_t                     ims;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->if_modified_since == NGX_HTTP_IMS_OFF) {
        return ngx_http_next_header_filter(r);
    }

    ims = ngx_http_parse_time(r->headers_in.if_modified_since->value.data,
                              r->headers_in.if_modified_since->value.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ims:%d lm:%d", ims, r->headers_out.last_modified_time);

    if (ims != r->headers_out.last_modified_time) {

        if (clcf->if_modified_since == NGX_HTTP_IMS_EXACT
            || ims < r->headers_out.last_modified_time)
        {
            return ngx_http_next_header_filter(r);
        }
    }

    r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_type.len = 0;
    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);

    if (r->headers_out.content_encoding) {
        r->headers_out.content_encoding->hash = 0;
        r->headers_out.content_encoding = NULL;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_not_modified_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_not_modified_header_filter;

    return NGX_OK;
}
