
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


typedef struct {
    ngx_connection_t                *connection;

    size_t                           init_window;
    size_t                           send_window;
    size_t                           recv_window;
    ngx_uint_t                       last_stream_id;
} ngx_http_proxy_v2_session_t;


ngx_int_t ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session, ngx_uint_t *stream_id);


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
