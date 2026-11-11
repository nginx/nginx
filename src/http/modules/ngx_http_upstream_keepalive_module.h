
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_upstream_keepalive_init(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *uscf);
void ngx_http_upstream_keepalive_drain(ngx_http_upstream_srv_conf_t *uscf);


#endif /* _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_ */
