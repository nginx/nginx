
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


typedef struct ngx_http_proxy_v2_session_s  ngx_http_proxy_v2_session_t;
typedef struct ngx_http_proxy_v2_stream_s   ngx_http_proxy_v2_stream_t;


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


struct ngx_http_proxy_v2_stream_s {
    ngx_http_request_t              *request;
    ngx_http_proxy_v2_session_t     *session;

    ngx_chain_t                     *in;
    ngx_chain_t                     *out;
    ngx_chain_t                     *free;
    ngx_chain_t                     *busy;

    ngx_uint_t                       id;

    off_t                            length;

    ssize_t                          send_window;
    size_t                           recv_window;

    ngx_uint_t                       fragment_state;
    ngx_uint_t                       index;
    ngx_str_t                        name;
    ngx_str_t                        value;

    u_char                          *field_end;
    size_t                           header_limit;
    size_t                           field_length;
    size_t                           field_rest;
    u_char                           field_state;

    unsigned                         literal:1;
    unsigned                         field_huffman:1;

    unsigned                         header_sent:1;
    unsigned                         output_closed:1;
    unsigned                         output_blocked:1;
    unsigned                         parsing_headers:1;
    unsigned                         end_stream:1;
    unsigned                         done:1;
    unsigned                         status:1;
    unsigned                         rst:1;
};


struct ngx_http_proxy_v2_session_s {
    ngx_connection_t                *connection;
    ngx_http_proxy_v2_stream_t      *stream;

    ngx_http_proxy_v2_state_e        state;
    ngx_uint_t                       frame_state;

    size_t                           rest;
    ngx_uint_t                       stream_id;
    u_char                           type;
    u_char                           flags;
    u_char                           padding;

    size_t                           init_window;
    size_t                           send_window;
    size_t                           recv_window;
    ngx_uint_t                       last_stream_id;
};


ngx_int_t ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session);
ngx_int_t ngx_http_proxy_v2_attach_stream(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_stream_t *stream);
void ngx_http_proxy_v2_detach_stream(ngx_http_proxy_v2_stream_t *stream);
ngx_int_t ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b);


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
