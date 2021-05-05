
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_STREAMS_H_INCLUDED_
#define _NGX_HTTP_V3_STREAMS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


void ngx_http_v3_init_uni_stream(ngx_connection_t *c);
ngx_int_t ngx_http_v3_register_uni_stream(ngx_connection_t *c, uint64_t type);

ngx_connection_t *ngx_http_v3_create_push_stream(ngx_connection_t *c,
    uint64_t push_id);
ngx_int_t ngx_http_v3_set_max_push_id(ngx_connection_t *c,
    uint64_t max_push_id);
ngx_int_t ngx_http_v3_cancel_push(ngx_connection_t *c, uint64_t push_id);
ngx_int_t ngx_http_v3_cancel_stream(ngx_connection_t *c, ngx_uint_t stream_id);

ngx_int_t ngx_http_v3_send_settings(ngx_connection_t *c);
ngx_int_t ngx_http_v3_send_goaway(ngx_connection_t *c, uint64_t id);
ngx_int_t ngx_http_v3_send_ref_insert(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value);
ngx_int_t ngx_http_v3_send_insert(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
ngx_int_t ngx_http_v3_send_set_capacity(ngx_connection_t *c,
    ngx_uint_t capacity);
ngx_int_t ngx_http_v3_send_duplicate(ngx_connection_t *c, ngx_uint_t index);
ngx_int_t ngx_http_v3_send_ack_header(ngx_connection_t *c,
    ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_send_cancel_stream(ngx_connection_t *c,
    ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_send_inc_insert_count(ngx_connection_t *c,
    ngx_uint_t inc);


#endif /* _NGX_HTTP_V3_STREAMS_H_INCLUDED_ */
