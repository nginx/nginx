#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_alloc.h>
#include <ngx_http.h>

#define NGX_HTTP_LOC_CONF  0

int ngx_http_config_modules(ngx_pool_t *pool, ngx_http_module_t **modules);


extern void **ngx_srv_conf;
extern void **ngx_loc_conf;


#endif _NGX_HTTP_CONFIG_H_INCLUDED_
