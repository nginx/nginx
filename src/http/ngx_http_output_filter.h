#ifndef _NGX_HTTP_OUTPUT_FILTER_H_INCLUDED_
#define _NGX_HTTP_OUTPUT_FILTER_H_INCLUDED_


#include <ngx_hunk.h>
#include <ngx_http.h>


#define NGX_HTTP_FILTER_NEED_IN_MEMORY  1
#define NGX_HTTP_FILTER_NEED_TEMP       2


typedef struct {
    size_t        hunk_size;
} ngx_http_output_filter_conf_t;


typedef struct {
    ngx_hunk_t   *hunk;
    ngx_chain_t  *in;
    ngx_chain_t   out;
    unsigned      last;
} ngx_http_output_filter_ctx_t;


extern ngx_module_t  ngx_http_output_filter_module;


#endif /* _NGX_HTTP_OUTPUT_FILTER_H_INCLUDED_ */
