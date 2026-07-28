
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_KEEPALIVE_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_KEEPALIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


void *ngx_http_proxy_v2_keepalive_create_main_conf(ngx_conf_t *cf);
char *ngx_http_proxy_v2_keepalive_init_main_conf(ngx_conf_t *cf, void *conf);

ngx_int_t ngx_http_proxy_v2_keepalive_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
void ngx_http_proxy_v2_keepalive_close_idle(ngx_connection_t *c);


#endif /* _NGX_HTTP_PROXY_V2_KEEPALIVE_H_INCLUDED_ */
