
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



static int ngx_http_not_modified_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_not_modified_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_not_modified_filter_module = {
    NGX_MODULE,
    &ngx_http_not_modified_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_not_modified_filter_init,     /* init module */
    NULL                                   /* init child */
};


static int (*next_header_filter) (ngx_http_request_t *r);


static int ngx_http_not_modified_header_filter(ngx_http_request_t *r)
{
    time_t  ims;

    if (r->headers_out.status != NGX_HTTP_OK
        || r->headers_in.if_modified_since == NULL
        || r->headers_out.last_modified_time == -1)
    {
        return next_header_filter(r);
    }

    ims = ngx_http_parse_time(r->headers_in.if_modified_since->value.data,
                              r->headers_in.if_modified_since->value.len);
    
    ngx_log_debug(r->connection->log, "%d %d" _
                  ims _ r->headers_out.last_modified_time);

    /* I think that the equality of the dates is correcter */

    if (ims != NGX_ERROR && ims == r->headers_out.last_modified_time) {
        r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n = -1;
        r->headers_out.content_length = NULL;
        r->headers_out.content_type->key.len = 0;
        r->headers_out.content_type = NULL;
        r->headers_out.accept_ranges->key.len = 0;
    }

    return next_header_filter(r);
}


static int ngx_http_not_modified_filter_init(ngx_cycle_t *cycle)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_not_modified_header_filter;

    return NGX_OK;
}
