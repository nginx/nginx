
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef enum {
    ngx_http_proxy_v2_st_start = 0,
    ngx_http_proxy_v2_st_length_2,
    ngx_http_proxy_v2_st_length_3,
    ngx_http_proxy_v2_st_type,
    ngx_http_proxy_v2_st_flags,
    ngx_http_proxy_v2_st_stream_id,
    ngx_http_proxy_v2_st_stream_id_2,
    ngx_http_proxy_v2_st_stream_id_3,
    ngx_http_proxy_v2_st_stream_id_4,
    ngx_http_proxy_v2_st_payload
} ngx_http_proxy_v2_state_e;


typedef struct {
    u_char                         length_0;
    u_char                         length_1;
    u_char                         length_2;
    u_char                         type;
    u_char                         flags;
    u_char                         stream_id_0;
    u_char                         stream_id_1;
    u_char                         stream_id_2;
    u_char                         stream_id_3;
} ngx_http_proxy_v2_frame_t;


typedef struct {
    ngx_http_proxy_v2_state_e      state;
    ngx_uint_t                     frame_state;

    size_t                         rest;
    ngx_uint_t                     stream_id;
    ngx_uint_t                     rst_stream_error;
    ngx_uint_t                     goaway_stream_id;
    ngx_uint_t                     goaway_error;
    ngx_uint_t                     window_update;
    ngx_uint_t                     setting_id;
    ngx_uint_t                     setting_value;
    u_char                         type;
    u_char                         flags;
    u_char                         padding;
    u_char                         ping_data[8];
} ngx_http_proxy_v2_parse_t;


ngx_int_t ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log);
ngx_int_t ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b);

/* NGX_OK means data is ready; NGX_DONE means the frame is done. */
ngx_int_t ngx_http_proxy_v2_parse_data(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log);

/* NGX_OK means the header block is ready; NGX_DONE means the frame is done. */
ngx_int_t ngx_http_proxy_v2_parse_headers(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log);
ngx_int_t ngx_http_proxy_v2_parse_headers_padding(
    ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_parse_rst_stream(
    ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b, ngx_log_t *log);
ngx_int_t ngx_http_proxy_v2_parse_goaway(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log);
ngx_int_t ngx_http_proxy_v2_parse_window_update(
    ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b, ngx_log_t *log);
ngx_int_t ngx_http_proxy_v2_parse_ping(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log);

/* NGX_OK means one setting is ready; NGX_DONE means there is no setting. */
ngx_int_t ngx_http_proxy_v2_parse_settings(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log);


#endif /* _NGX_HTTP_PROXY_V2_FRAME_H_INCLUDED_ */
