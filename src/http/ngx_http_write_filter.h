#ifndef _NGX_HTTP_WRITE_FILTER_H_INCLUDED_
#define _NGX_HTTP_WRITE_FILTER_H_INCLUDED_


#include <ngx_hunk.h>
#include <ngx_http.h>


typedef struct {
    size_t        buffer_output;
} ngx_http_write_filter_conf_t;

typedef struct {
    ngx_chain_t  *out;
} ngx_http_write_filter_ctx_t;


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in);


#endif /* _NGX_HTTP_WRITE_FILTER_H_INCLUDED_ */
