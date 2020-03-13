
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_H_INCLUDED_
#define _NGX_HTTP_V3_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_V3_STREAM             0x48335354   /* "H3ST" */


#define NGX_HTTP_V3_VARLEN_INT_LEN     4
#define NGX_HTTP_V3_PREFIX_INT_LEN     11


typedef struct {
    ngx_http_connection_t   hc;

    ngx_array_t            *dynamic;

    ngx_connection_t       *client_encoder;
    ngx_connection_t       *client_decoder;
    ngx_connection_t       *server_encoder;
    ngx_connection_t       *server_decoder;
} ngx_http_v3_connection_t;


typedef struct {
    ngx_str_t               name;
    ngx_str_t               value;
} ngx_http_v3_header_t;


ngx_int_t ngx_http_v3_parse_header(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t pseudo);
ngx_chain_t *ngx_http_v3_create_header(ngx_http_request_t *r);


uintptr_t ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value);
uintptr_t ngx_http_v3_encode_prefix_int(u_char *p, uint64_t value,
    ngx_uint_t prefix);
uint64_t ngx_http_v3_decode_varlen_int(u_char *p);
int64_t ngx_http_v3_decode_prefix_int(u_char **src, size_t len,
    ngx_uint_t prefix);
ngx_int_t ngx_http_v3_decode_huffman(ngx_connection_t *c, ngx_str_t *s);

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
