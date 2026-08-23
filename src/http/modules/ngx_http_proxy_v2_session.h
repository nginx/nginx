
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


#include <ngx_http_proxy_v2_frame.h>


typedef struct {
    ngx_http_proxy_v2_frame_parse_t  frame_parse;

    ngx_connection_t                *connection;
    ngx_http_request_t              *request;
    ngx_buf_t                       *input;

    u_char                           output[NGX_HTTP_V2_FRAME_HEADER_SIZE
                                            + NGX_HTTP_PROXY_V2_PING_SIZE];
    u_char                          *output_pos;
    u_char                          *output_last;

    size_t                           frame_size;

    size_t                           init_window;
    size_t                           send_window;
    size_t                           recv_window;
    ngx_uint_t                       last_stream_id;
    ngx_uint_t                       peer_last_stream_id;
    ngx_uint_t                       goaway_error;
    ngx_uint_t                       connection_error;

    unsigned                         frame_header:1;
    unsigned                         frame_ready:1;
    unsigned                         frame_error:1;
    unsigned                         frame_dispatched:1;
    unsigned                         output_blocked:1;
    unsigned                         goaway:1;
} ngx_http_proxy_v2_session_t;


void ngx_http_proxy_v2_session_init(ngx_http_proxy_v2_session_t *s);
void ngx_http_proxy_v2_session_attach(ngx_http_proxy_v2_session_t *s,
    ngx_connection_t *c, ngx_http_request_t *r);
void ngx_http_proxy_v2_session_detach(ngx_http_proxy_v2_session_t *s,
    ngx_http_request_t *r);
void ngx_http_proxy_v2_session_frame_done(ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_process_ping(
    ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_process_window_update(
    ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_process_settings(
    ngx_http_proxy_v2_session_t *s, ssize_t *window_update);
ngx_int_t ngx_http_proxy_v2_session_process_goaway(
    ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_send(ngx_http_proxy_v2_session_t *s);


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
