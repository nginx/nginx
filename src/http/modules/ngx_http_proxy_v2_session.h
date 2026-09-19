
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


typedef struct ngx_http_proxy_v2_session_s  ngx_http_proxy_v2_session_t;
typedef struct ngx_http_proxy_v2_stream_s   ngx_http_proxy_v2_stream_t;


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


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
