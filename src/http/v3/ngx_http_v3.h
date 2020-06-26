
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_H_INCLUDED_
#define _NGX_HTTP_V3_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v3_parse.h>


#define NGX_HTTP_V3_ALPN(s)         NGX_HTTP_V3_ALPN_DRAFT(s)
#define NGX_HTTP_V3_ALPN_DRAFT(s)   "\x05h3-" #s
#define NGX_HTTP_V3_ALPN_ADVERTISE  NGX_HTTP_V3_ALPN(NGX_QUIC_DRAFT_VERSION)

#define NGX_HTTP_V3_VARLEN_INT_LEN                 4
#define NGX_HTTP_V3_PREFIX_INT_LEN                 11

#define NGX_HTTP_V3_STREAM_CONTROL                 0x00
#define NGX_HTTP_V3_STREAM_PUSH                    0x01
#define NGX_HTTP_V3_STREAM_ENCODER                 0x02
#define NGX_HTTP_V3_STREAM_DECODER                 0x03

#define NGX_HTTP_V3_FRAME_DATA                     0x00
#define NGX_HTTP_V3_FRAME_HEADERS                  0x01
#define NGX_HTTP_V3_FRAME_CANCEL_PUSH              0x03
#define NGX_HTTP_V3_FRAME_SETTINGS                 0x04
#define NGX_HTTP_V3_FRAME_PUSH_PROMISE             0x05
#define NGX_HTTP_V3_FRAME_GOAWAY                   0x07
#define NGX_HTTP_V3_FRAME_MAX_PUSH_ID              0x0d

#define NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY       0x01
#define NGX_HTTP_V3_PARAM_MAX_HEADER_LIST_SIZE     0x06
#define NGX_HTTP_V3_PARAM_BLOCKED_STREAMS          0x07

#define NGX_HTTP_V3_STREAM_CLIENT_CONTROL          0
#define NGX_HTTP_V3_STREAM_SERVER_CONTROL          1
#define NGX_HTTP_V3_STREAM_CLIENT_ENCODER          2
#define NGX_HTTP_V3_STREAM_SERVER_ENCODER          3
#define NGX_HTTP_V3_STREAM_CLIENT_DECODER          4
#define NGX_HTTP_V3_STREAM_SERVER_DECODER          5
#define NGX_HTTP_V3_MAX_KNOWN_STREAM               6


typedef struct {
    ngx_quic_tp_t           quic;
} ngx_http_v3_srv_conf_t;


typedef struct {
    ngx_http_connection_t   hc;

    ngx_array_t            *dynamic;
    ngx_connection_t       *known_streams[NGX_HTTP_V3_MAX_KNOWN_STREAM];
} ngx_http_v3_connection_t;


#define ngx_http_v3_get_module_srv_conf(c, module)                            \
    ngx_http_get_module_srv_conf(                                             \
             ((ngx_http_v3_connection_t *) c->qs->parent->data)->hc.conf_ctx, \
             module)


typedef struct {
    ngx_str_t               name;
    ngx_str_t               value;
} ngx_http_v3_header_t;


ngx_int_t ngx_http_v3_parse_request(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_header(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t allow_underscores);
ngx_int_t ngx_http_v3_parse_request_body(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_chunked_t *ctx);
ngx_chain_t *ngx_http_v3_create_header(ngx_http_request_t *r);
ngx_chain_t *ngx_http_v3_create_trailers(ngx_http_request_t *r);

uintptr_t ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value);
uintptr_t ngx_http_v3_encode_prefix_int(u_char *p, uint64_t value,
    ngx_uint_t prefix);

void ngx_http_v3_handle_client_uni_stream(ngx_connection_t *c);

ngx_int_t ngx_http_v3_ref_insert(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value);
ngx_int_t ngx_http_v3_insert(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
ngx_int_t ngx_http_v3_set_capacity(ngx_connection_t *c, ngx_uint_t capacity);
ngx_int_t ngx_http_v3_duplicate(ngx_connection_t *c, ngx_uint_t index);
ngx_int_t ngx_http_v3_ack_header(ngx_connection_t *c, ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_cancel_stream(ngx_connection_t *c, ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_inc_insert_count(ngx_connection_t *c, ngx_uint_t inc);
ngx_http_v3_header_t *ngx_http_v3_lookup_table(ngx_connection_t *c,
    ngx_uint_t dynamic, ngx_uint_t index);
ngx_int_t ngx_http_v3_check_insert_count(ngx_connection_t *c,
    ngx_uint_t insert_count);
ngx_int_t ngx_http_v3_set_param(ngx_connection_t *c, uint64_t id,
    uint64_t value);

ngx_int_t ngx_http_v3_client_ref_insert(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value);
ngx_int_t ngx_http_v3_client_insert(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
ngx_int_t ngx_http_v3_client_set_capacity(ngx_connection_t *c,
    ngx_uint_t capacity);
ngx_int_t ngx_http_v3_client_duplicate(ngx_connection_t *c, ngx_uint_t index);
ngx_int_t ngx_http_v3_client_ack_header(ngx_connection_t *c,
    ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_client_cancel_stream(ngx_connection_t *c,
    ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_client_inc_insert_count(ngx_connection_t *c,
    ngx_uint_t inc);


extern ngx_module_t  ngx_http_v3_module;


#endif /* _NGX_HTTP_V3_H_INCLUDED_ */
