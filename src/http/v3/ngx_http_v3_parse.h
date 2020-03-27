
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_PARSE_H_INCLUDED_
#define _NGX_HTTP_V3_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t                      state;
    uint64_t                        value;
} ngx_http_v3_parse_varlen_int_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      mask;
    uint64_t                        value;
} ngx_http_v3_parse_prefix_int_t;


typedef struct {
    ngx_uint_t                      state;
    uint64_t                        id;
    ngx_http_v3_parse_varlen_int_t  vlint;
} ngx_http_v3_parse_settings_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      insert_count;
    ngx_uint_t                      delta_base;
    ngx_uint_t                      sign;
    ngx_uint_t                      base;
    ngx_http_v3_parse_prefix_int_t  pint;
} ngx_http_v3_parse_header_block_prefix_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      length;
    ngx_uint_t                      huffman;
    ngx_str_t                       value;
    u_char                         *last;
    u_char                          huffstate;
} ngx_http_v3_parse_literal_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      index;
    ngx_uint_t                      base;
    ngx_uint_t                      dynamic;

    ngx_str_t                       name;
    ngx_str_t                       value;

    ngx_http_v3_parse_prefix_int_t  pint;
    ngx_http_v3_parse_literal_t     literal;
} ngx_http_v3_parse_header_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_header_t      header;
} ngx_http_v3_parse_header_rep_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_header_block_prefix_t  prefix;
    ngx_http_v3_parse_header_rep_t  header_rep;
} ngx_http_v3_parse_headers_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_header_t      header;
    ngx_http_v3_parse_prefix_int_t  pint;
} ngx_http_v3_parse_encoder_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_prefix_int_t  pint;
} ngx_http_v3_parse_decoder_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_settings_t    settings;
} ngx_http_v3_parse_control_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
} ngx_http_v3_parse_data_t;


ngx_int_t ngx_http_v3_parse_varlen_int(ngx_connection_t *c,
    ngx_http_v3_parse_varlen_int_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_prefix_int(ngx_connection_t *c,
    ngx_http_v3_parse_prefix_int_t *st, ngx_uint_t prefix, u_char ch);

ngx_int_t ngx_http_v3_parse_headers(ngx_connection_t *c,
    ngx_http_v3_parse_headers_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_block_prefix(ngx_connection_t *c,
    ngx_http_v3_parse_header_block_prefix_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_rep(ngx_connection_t *c,
    ngx_http_v3_parse_header_rep_t *st, ngx_uint_t base, u_char ch);
ngx_int_t ngx_http_v3_parse_literal(ngx_connection_t *c,
    ngx_http_v3_parse_literal_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_ri(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_lri(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_l(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_pbi(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_lpbi(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);

ngx_int_t ngx_http_v3_parse_control(ngx_connection_t *c, void *data, u_char ch);
ngx_int_t ngx_http_v3_parse_settings(ngx_connection_t *c,
    ngx_http_v3_parse_settings_t *st, u_char ch);

ngx_int_t ngx_http_v3_parse_encoder(ngx_connection_t *c, void *data, u_char ch);
ngx_int_t ngx_http_v3_parse_header_inr(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);
ngx_int_t ngx_http_v3_parse_header_iwnr(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch);

ngx_int_t ngx_http_v3_parse_decoder(ngx_connection_t *c, void *data, u_char ch);

ngx_int_t ngx_http_v3_parse_data(ngx_connection_t *c,
    ngx_http_v3_parse_data_t *st, u_char ch);


#endif /* _NGX_HTTP_V3_PARSE_H_INCLUDED_ */
