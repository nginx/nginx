#ifndef _NGX_HTTP_FILTER_H_INCLUDED_
#define _NGX_HTTP_FILTER_H_INCLUDED_


#define NGX_HTTP_FILTER_NEED_IN_MEMORY      1
#define NGX_HTTP_FILTER_SSI_NEED_IN_MEMORY  2
#define NGX_HTTP_FILTER_NEED_TEMP           4


int ngx_http_output_filter(ngx_http_request_t *r, ngx_hunk_t *hunk);
int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in);


extern int (*ngx_http_top_header_filter) (ngx_http_request_t *r);
extern int (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


#endif /* _NGX_HTTP_FILTER_H_INCLUDED_ */
