#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_http.h>


typedef struct {
    int dummy;
} ngx_http_core_conf_t;


typedef struct {
    int dummy;
} ngx_http_core_srv_conf_t;


typedef struct {
    time_t  send_timeout;
} ngx_http_core_loc_conf_t;


extern ngx_http_module_t  ngx_http_core_module_ctx;
extern ngx_module_t  ngx_http_core_module;

extern int (*ngx_http_top_header_filter) (ngx_http_request_t *r);
extern int ngx_http_max_module;


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
