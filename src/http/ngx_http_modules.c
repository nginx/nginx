
#include <ngx_http.h>

extern ngx_http_module_t ngx_http_header_filter_module;

extern ngx_http_module_t ngx_http_write_filter_module;
extern ngx_http_module_t ngx_http_output_filter_module;

extern ngx_http_module_t ngx_http_core_module;
extern ngx_http_module_t ngx_http_index_module;

ngx_http_module_t *ngx_http_modules[] = {

    &ngx_http_header_filter_module,

    &ngx_http_write_filter_module,
    &ngx_http_output_filter_module,

    &ngx_http_index_module,
    &ngx_http_core_module,

    NULL
};
