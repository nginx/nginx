#ifndef _NGX_HTTP_FILTER_H_INCLUDED_
#define _NGX_HTTP_FILTER_H_INCLUDED_


#define NGX_HTTP_FILTER_NEED_IN_MEMORY      1
#define NGX_HTTP_FILTER_SSI_NEED_IN_MEMORY  2
#define NGX_HTTP_FILTER_NEED_TEMP           4
#define NGX_HTTP_FILTER_ALLOW_RANGES        8


typedef int (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef int (*ngx_http_output_body_filter_pt)
                                   (ngx_http_request_t *r, ngx_chain_t *chain);


int ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


extern ngx_http_output_header_filter_pt  ngx_http_top_header_filter;
extern ngx_http_output_body_filter_pt    ngx_http_top_body_filter;


#endif /* _NGX_HTTP_FILTER_H_INCLUDED_ */
