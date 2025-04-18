
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
#include <ngx_http_v3_encode.h>
#include <ngx_http_v3_uni.h>
#include <ngx_http_v3_table.h>


#define NGX_HTTP_V3_ALPN_PROTO                     "\x02h3"
#define NGX_HTTP_V3_HQ_ALPN_PROTO                  "\x0Ahq-interop"
#define NGX_HTTP_V3_HQ_PROTO                       "hq-interop"

#define NGX_HTTP_V3_VARLEN_INT_LEN                 8
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
#define NGX_HTTP_V3_PARAM_MAX_FIELD_SECTION_SIZE   0x06
#define NGX_HTTP_V3_PARAM_BLOCKED_STREAMS          0x07

#define NGX_HTTP_V3_MAX_TABLE_CAPACITY             4096

#define NGX_HTTP_V3_STREAM_CLIENT_CONTROL          0
#define NGX_HTTP_V3_STREAM_SERVER_CONTROL          1
#define NGX_HTTP_V3_STREAM_CLIENT_ENCODER          2
#define NGX_HTTP_V3_STREAM_SERVER_ENCODER          3
#define NGX_HTTP_V3_STREAM_CLIENT_DECODER          4
#define NGX_HTTP_V3_STREAM_SERVER_DECODER          5
#define NGX_HTTP_V3_MAX_KNOWN_STREAM               6
#define NGX_HTTP_V3_MAX_UNI_STREAMS                3

/* HTTP/3 errors */
#define NGX_HTTP_V3_ERR_NO_ERROR                   0x100
#define NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR     0x101
#define NGX_HTTP_V3_ERR_INTERNAL_ERROR             0x102
#define NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR      0x103
#define NGX_HTTP_V3_ERR_CLOSED_CRITICAL_STREAM     0x104
#define NGX_HTTP_V3_ERR_FRAME_UNEXPECTED           0x105
#define NGX_HTTP_V3_ERR_FRAME_ERROR                0x106
#define NGX_HTTP_V3_ERR_EXCESSIVE_LOAD             0x107
#define NGX_HTTP_V3_ERR_ID_ERROR                   0x108
#define NGX_HTTP_V3_ERR_SETTINGS_ERROR             0x109
#define NGX_HTTP_V3_ERR_MISSING_SETTINGS           0x10a
#define NGX_HTTP_V3_ERR_REQUEST_REJECTED           0x10b
#define NGX_HTTP_V3_ERR_REQUEST_CANCELLED          0x10c
#define NGX_HTTP_V3_ERR_REQUEST_INCOMPLETE         0x10d
#define NGX_HTTP_V3_ERR_CONNECT_ERROR              0x10f
#define NGX_HTTP_V3_ERR_VERSION_FALLBACK           0x110

/* QPACK errors */
#define NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED       0x200
#define NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR       0x201
#define NGX_HTTP_V3_ERR_DECODER_STREAM_ERROR       0x202


#define ngx_http_v3_get_session(c)                                            \
    ((ngx_http_v3_session_t *) ((c)->quic ? (c)->quic->parent->data           \
                                          : (c)->data))

#define ngx_http_quic_get_connection(c)                                       \
    (ngx_http_v3_get_session(c)->http_connection)

#define ngx_http_v3_get_module_loc_conf(c, module)                            \
    ngx_http_get_module_loc_conf(ngx_http_quic_get_connection(c)->conf_ctx,   \
                                 module)

#define ngx_http_v3_get_module_srv_conf(c, module)                            \
    ngx_http_get_module_srv_conf(ngx_http_quic_get_connection(c)->conf_ctx,   \
                                 module)

#define ngx_http_v3_finalize_connection(c, code, reason)                      \
    ngx_quic_finalize_connection((c)->quic ? (c)->quic->parent : (c),         \
                                 code, reason)

#define ngx_http_v3_shutdown_connection(c, code, reason)                      \
    ngx_quic_shutdown_connection((c)->quic ? (c)->quic->parent : (c),         \
                                 code, reason)


typedef struct {
    ngx_flag_t                    enable;
    ngx_flag_t                    enable_hq;
    size_t                        max_table_capacity;
    ngx_uint_t                    max_blocked_streams;
    ngx_uint_t                    max_concurrent_streams;
    ngx_quic_conf_t               quic;
} ngx_http_v3_srv_conf_t;


struct ngx_http_v3_parse_s {
    size_t                        header_limit;
    ngx_http_v3_parse_headers_t   headers;
    ngx_http_v3_parse_data_t      body;
    ngx_array_t                  *cookies;
};


struct ngx_http_v3_session_s {
    ngx_http_connection_t        *http_connection;

    ngx_http_v3_dynamic_table_t   table;

    ngx_event_t                   keepalive;
    ngx_uint_t                    nrequests;

    ngx_queue_t                   blocked;
    ngx_uint_t                    nblocked;

    uint64_t                      next_request_id;

    off_t                         total_bytes;
    off_t                         payload_bytes;

    unsigned                      goaway:1;
    unsigned                      hq:1;

    ngx_connection_t             *known_streams[NGX_HTTP_V3_MAX_KNOWN_STREAM];
};


void ngx_http_v3_init_stream(ngx_connection_t *c);
void ngx_http_v3_reset_stream(ngx_connection_t *c);
ngx_int_t ngx_http_v3_init_session(ngx_connection_t *c);
ngx_int_t ngx_http_v3_check_flood(ngx_connection_t *c);
ngx_int_t ngx_http_v3_init(ngx_connection_t *c);
void ngx_http_v3_shutdown(ngx_connection_t *c);

ngx_int_t ngx_http_v3_read_request_body(ngx_http_request_t *r);
ngx_int_t ngx_http_v3_read_unbuffered_request_body(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_v3_module;


#endif /* _NGX_HTTP_V3_H_INCLUDED_ */
