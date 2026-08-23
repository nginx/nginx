
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


#include <ngx_http_proxy_v2_frame.h>


typedef struct ngx_http_proxy_v2_session_s  ngx_http_proxy_v2_session_t;
typedef struct ngx_http_proxy_v2_stream_s   ngx_http_proxy_v2_stream_t;
typedef struct ngx_http_proxy_v2_in_frame_s ngx_http_proxy_v2_in_frame_t;


struct ngx_http_proxy_v2_in_frame_s {
    ngx_http_proxy_v2_frame_parse_t  parse;
    ngx_buf_t                        buffer;
    ngx_http_proxy_v2_in_frame_t    *next;

    unsigned                         error:1;
    unsigned                         parsed:1;
};


struct ngx_http_proxy_v2_stream_s {
    ngx_rbtree_node_t                node;

    ngx_http_request_t              *request;
    ngx_http_proxy_v2_session_t     *session;
    ngx_connection_t                *connection;

    ngx_uint_t                       id;
    ssize_t                          send_window;
    size_t                           recv_window;

    ngx_http_proxy_v2_in_frame_t    *frames;
    ngx_http_proxy_v2_in_frame_t    *recv_frame;
    ngx_http_proxy_v2_in_frame_t    *free_frames;
    ngx_http_proxy_v2_in_frame_t   **last_frame;

    unsigned                         goaway:1;
    unsigned                         unprocessed:1;
    unsigned                         registered:1;
};


struct ngx_http_proxy_v2_session_s {
    ngx_http_proxy_v2_frame_parse_t  frame_parse;

    ngx_connection_t                *connection;
    ngx_http_proxy_v2_stream_t      *stream;
    ngx_buf_t                       *input;

    ngx_rbtree_t                     streams;
    ngx_rbtree_node_t                streams_sentinel;

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
    unsigned                         output_blocked:1;
    unsigned                         goaway:1;
};


ngx_http_proxy_v2_stream_t *ngx_http_proxy_v2_stream_create(ngx_pool_t *pool,
    ngx_http_request_t *r);
void ngx_http_proxy_v2_stream_reset_frames(
    ngx_http_proxy_v2_stream_t *stream);
ngx_http_proxy_v2_in_frame_t *ngx_http_proxy_v2_stream_peek_frame(
    ngx_http_proxy_v2_stream_t *stream);
ngx_http_proxy_v2_in_frame_t *ngx_http_proxy_v2_stream_dequeue_frame(
    ngx_http_proxy_v2_stream_t *stream);
void ngx_http_proxy_v2_stream_free_frame(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_proxy_v2_in_frame_t *frame);
void ngx_http_proxy_v2_session_init(ngx_http_proxy_v2_session_t *s);
ngx_http_proxy_v2_session_t *ngx_http_proxy_v2_session_create(
    ngx_connection_t *c);
ngx_http_proxy_v2_session_t *ngx_http_proxy_v2_session_get(
    ngx_connection_t *c);
ngx_int_t ngx_http_proxy_v2_session_register_stream(
    ngx_http_proxy_v2_session_t *s, ngx_http_proxy_v2_stream_t *stream);
ngx_http_proxy_v2_stream_t *ngx_http_proxy_v2_session_find_stream(
    ngx_http_proxy_v2_session_t *s, ngx_uint_t stream_id);
void ngx_http_proxy_v2_session_unregister_stream(
    ngx_http_proxy_v2_session_t *s, ngx_http_proxy_v2_stream_t *stream);
ngx_int_t ngx_http_proxy_v2_session_attach(ngx_http_proxy_v2_session_t *s,
    ngx_connection_t *c, ngx_http_proxy_v2_stream_t *stream);
void ngx_http_proxy_v2_session_detach(ngx_http_proxy_v2_session_t *s,
    ngx_http_proxy_v2_stream_t *stream);
ngx_int_t ngx_http_proxy_v2_session_process_connection_frame(
    ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_dispatch_stream_frame(
    ngx_http_proxy_v2_session_t *s);
void ngx_http_proxy_v2_session_frame_done(ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_process_ping(
    ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_process_window_update(
    ngx_http_proxy_v2_session_t *s);
ngx_int_t ngx_http_proxy_v2_session_process_settings(
    ngx_http_proxy_v2_session_t *s, ssize_t *window_update);
ngx_int_t ngx_http_proxy_v2_session_process_goaway(
    ngx_http_proxy_v2_session_t *s);
void ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev);
ngx_int_t ngx_http_proxy_v2_session_send(ngx_http_proxy_v2_session_t *s);


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
