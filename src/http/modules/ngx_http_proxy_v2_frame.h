
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_


#define NGX_HTTP_PROXY_V2_PING_SIZE  8

#define NGX_HTTP_PROXY_V2_PROTOCOL_ERROR  0x1


typedef struct {
    size_t      length;
    ngx_uint_t  stream_id;
    u_char      type;
    u_char      flags;
    u_char      state;
} ngx_http_proxy_v2_frame_parse_t;


typedef struct {
    ngx_uint_t  initial_window;

    unsigned    ack:1;
    unsigned    initial_window_set:1;
} ngx_http_proxy_v2_settings_t;


typedef struct {
    ngx_uint_t  last_stream_id;
    ngx_uint_t  error;
    ngx_str_t   debug;
} ngx_http_proxy_v2_goaway_t;


ngx_int_t ngx_http_proxy_v2_frame_parse(ngx_http_proxy_v2_frame_parse_t *parse,
    ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_frame_parse_ping(
    ngx_http_proxy_v2_frame_parse_t *parse, ngx_buf_t *b, u_char *data);
ngx_int_t ngx_http_proxy_v2_frame_parse_window_update(
    ngx_http_proxy_v2_frame_parse_t *parse, ngx_buf_t *b,
    ngx_uint_t *increment);
ngx_int_t ngx_http_proxy_v2_frame_parse_settings(
    ngx_http_proxy_v2_frame_parse_t *parse, ngx_buf_t *b,
    ngx_http_proxy_v2_settings_t *settings);
ngx_int_t ngx_http_proxy_v2_frame_parse_goaway(
    ngx_http_proxy_v2_frame_parse_t *parse, ngx_buf_t *b,
    ngx_http_proxy_v2_goaway_t *goaway);


#endif /* _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_ */
