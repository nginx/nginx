
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    size_t                         init_window;
    size_t                         send_window;
    size_t                         recv_window;
    ngx_uint_t                     last_stream_id;

    ngx_uint_t                     header_state;
    size_t                         length;
    ngx_uint_t                     stream_id;
    u_char                         type;
    u_char                         flags;

    size_t                         ping_length;
    u_char                         ping_data[8];
} ngx_http_proxy_v2_session_t;


ngx_http_proxy_v2_session_t *ngx_http_proxy_v2_create_session(ngx_pool_t *pool);
ngx_http_proxy_v2_session_t *ngx_http_proxy_v2_get_session(
    ngx_peer_connection_t *pc);

ngx_int_t ngx_http_proxy_v2_parse_frame_header(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b, ngx_log_t *log);
ngx_int_t ngx_http_proxy_v2_parse_ping_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b, ngx_log_t *log);


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
