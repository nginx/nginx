
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_module.h>


ngx_int_t ngx_http_proxy_v2_process_body_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_conn_t *h2c,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_process_buffered_frame(ngx_event_pipe_t *p,
    ngx_http_request_t *r, ngx_http_proxy_v2_conn_t *h2c,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);


#endif /* _NGX_HTTP_PROXY_V2_UPSTREAM_H_INCLUDED_ */
