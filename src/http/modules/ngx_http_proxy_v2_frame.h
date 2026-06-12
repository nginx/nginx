/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_


#include <ngx_http_proxy_v2_module.h>


ngx_int_t ngx_http_proxy_v2_parse_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_parse_payload(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, ngx_uint_t body);


#endif /* _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_ */
