
#include <ngx_config_file.h>


extern ngx_module_t  ngx_http_header_filter_module;

extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_output_filter_module;

extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_index_module;

extern ngx_module_t  ngx_http_module;


ngx_module_t *ngx_modules[] = {

    &ngx_http_header_filter_module,

    &ngx_http_write_filter_module,
    &ngx_http_output_filter_module,

    &ngx_http_index_module,
    &ngx_http_core_module,

    &ngx_http_module,

    NULL
};
