#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_alloc.h>
#include <ngx_http.h>


typedef struct {
    void        **srv_conf;
    void        **loc_conf;
} ngx_http_conf_ctx_t;


#define NGX_HTTP_MAIN_CONF        0x1000000
#define NGX_HTTP_SRV_CONF         0x2000000
#define NGX_HTTP_LOC_CONF         0x6000000

#define NGX_HTTP_SRV_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, loc_conf)


int ngx_http_config_modules(ngx_pool_t *pool, ngx_module_t **modules);


extern ngx_module_t  ngx_http_module;


extern int (*ngx_http_top_header_filter) (ngx_http_request_t *r);

extern void **ngx_srv_conf;
extern void **ngx_loc_conf;


#endif _NGX_HTTP_CONFIG_H_INCLUDED_
