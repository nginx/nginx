/*
 * Copyright (C) nginx, Inc.
 */


#ifndef _NGX_HTTP_ACME_TLS_H_INCLUDED_
#define _NGX_HTTP_ACME_TLS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HTTP_ACME_TLS && NGX_HTTP_SSL)

#define NGX_HTTP_ACME_TLS_MODE_OFF       0
#define NGX_HTTP_ACME_TLS_MODE_INTERNAL  1
#define NGX_HTTP_ACME_TLS_MODE_PROXY     2

typedef struct {
    ngx_uint_t                 mode;          /* off, internal, proxy */
    ngx_str_t                  upstream;      /* for proxy mode */
    ngx_http_upstream_conf_t   upstream_conf; /* for proxy mode */
} ngx_http_acme_tls_srv_conf_t;

typedef struct {
    ngx_http_upstream_conf_t   upstream;
} ngx_http_acme_tls_loc_conf_t;

void ngx_http_acme_tls_proxy(ngx_connection_t *c);

extern ngx_module_t ngx_http_acme_tls_module;

#endif /* NGX_HTTP_ACME_TLS && NGX_HTTP_SSL */

#endif /* _NGX_HTTP_ACME_TLS_H_INCLUDED_ */