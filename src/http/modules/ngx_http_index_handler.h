#ifndef _NGX_HTTP_INDEX_HANDLER_H_INCLUDED_
#define _NGX_HTTP_INDEX_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DEFAULT_INDEX   "index.html"


typedef struct {
    ngx_array_t  indices;
    size_t       max_index_len;
} ngx_http_index_conf_t;


extern ngx_module_t  ngx_http_index_module;


#endif /* _NGX_HTTP_INDEX_HANDLER_H_INCLUDED_ */
