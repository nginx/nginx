
#include <ngx_config.h>

#include <ngx_conf_file.h>


extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;

extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_output_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;

extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_proxy_module;


ngx_module_t *ngx_modules[] = {

    &ngx_http_module,

    &ngx_http_core_module,
    &ngx_http_write_filter_module,
    &ngx_http_output_filter_module,
    &ngx_http_header_filter_module,

    /* &ngx_http_gzip_filter_module, */
    /* &ngx_http_range_filter_module, */
    /* &ngx_http_ssi_filter_module, */

    &ngx_http_index_module,
    &ngx_http_proxy_module,

    NULL
};
