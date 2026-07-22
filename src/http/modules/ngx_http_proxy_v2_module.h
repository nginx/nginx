
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>


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
    ngx_http_proxy_v2_st_payload,
    ngx_http_proxy_v2_st_padding
} ngx_http_proxy_v2_state_e;


typedef enum {
    ngx_http_proxy_v2_read_phase_header = 0,
    ngx_http_proxy_v2_read_phase_non_buffered,
    ngx_http_proxy_v2_read_phase_buffered
} ngx_http_proxy_v2_read_phase_e;


typedef struct {
    ngx_buf_t                      buffer;
    ngx_chain_writer_ctx_t         writer;
    ngx_chain_t                   *busy;
    size_t                         init_window;
    size_t                         send_window;
    size_t                         recv_window;
    ngx_uint_t                     last_stream_id;
} ngx_http_proxy_v2_conn_t;


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_http_proxy_v2_state_e      state;
    ngx_http_proxy_v2_read_phase_e read_phase;
    ngx_uint_t                     frame_state;
    ngx_uint_t                     fragment_state;

    ngx_chain_t                   *in;
    ngx_chain_t                   *out;
    ngx_chain_t                   *pending;
    ngx_chain_t                   *free;

    ngx_http_proxy_v2_conn_t      *connection;

    ngx_uint_t                     id;

    ngx_uint_t                     pings;
    ngx_uint_t                     settings;

    off_t                          length;

    ssize_t                        send_window;
    size_t                         recv_window;

    size_t                         rest;
    ngx_uint_t                     stream_id;
    u_char                         type;
    u_char                         flags;
    u_char                         padding;

    ngx_uint_t                     error;
    ngx_uint_t                     window_update;

    ngx_uint_t                     setting_id;
    ngx_uint_t                     setting_value;
    ngx_int_t                      parsed_rc;

    u_char                         ping_data[8];

    ngx_uint_t                     index;
    ngx_str_t                      name;
    ngx_str_t                      value;

    u_char                        *field_end;
    size_t                         header_limit;
    size_t                         field_length;
    size_t                         field_rest;
    u_char                         field_state;

    unsigned                       literal:1;
    unsigned                       field_huffman:1;

    unsigned                       header_sent:1;
    unsigned                       output_closed:1;
    unsigned                       output_blocked:1;
    unsigned                       parsing_headers:1;
    unsigned                       header_initialized:1;
    unsigned                       end_stream:1;
    unsigned                       done:1;
    unsigned                       parsed:1;
    unsigned                       status:1;
    unsigned                       rst:1;
    unsigned                       goaway:1;
} ngx_http_proxy_v2_ctx_t;


ngx_int_t ngx_http_proxy_v2_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_proxy_v2_upstream_create(ngx_http_request_t *r);
void ngx_http_proxy_v2_upstream_init(ngx_http_request_t *r);
ngx_int_t ngx_http_proxy_v2_event_pipe_add_free_buf(ngx_event_pipe_t *p,
    ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_append_chain(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_chain_t *out);
ngx_int_t ngx_http_proxy_v2_flush_output(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
ngx_int_t ngx_http_proxy_v2_process_frame_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_uint_t body);
ngx_int_t ngx_http_proxy_v2_process_frame_payload(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_uint_t body);

extern ngx_module_t  ngx_http_proxy_v2_module;

#define ngx_http_proxy_v2_frame_tag                                      \
    (ngx_buf_tag_t) &ngx_http_proxy_v2_module


#endif /* _NGX_HTTP_PROXY_V2_H_INCLUDED_ */
