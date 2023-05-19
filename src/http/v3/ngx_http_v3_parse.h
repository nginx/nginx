
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
    ngx_uint_t                      shift;
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
} ngx_http_v3_parse_field_section_prefix_t;


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
} ngx_http_v3_parse_field_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_field_t       field;
} ngx_http_v3_parse_field_rep_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_field_section_prefix_t  prefix;
    ngx_http_v3_parse_field_rep_t   field_rep;
} ngx_http_v3_parse_headers_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_field_t       field;
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
    ngx_http_v3_parse_varlen_int_t  vlint;
    union {
        ngx_http_v3_parse_encoder_t  encoder;
        ngx_http_v3_parse_decoder_t  decoder;
        ngx_http_v3_parse_control_t  control;
    } u;
} ngx_http_v3_parse_uni_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
} ngx_http_v3_parse_data_t;


/*
 * Parse functions return codes:
 *   NGX_DONE - parsing done
 *   NGX_OK - sub-element done
 *   NGX_AGAIN - more data expected
 *   NGX_BUSY - waiting for external event
 *   NGX_ERROR - internal error
 *   NGX_HTTP_V3_ERROR_XXX - HTTP/3 or QPACK error
 */

ngx_int_t ngx_http_v3_parse_headers(ngx_connection_t *c,
    ngx_http_v3_parse_headers_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_data(ngx_connection_t *c,
    ngx_http_v3_parse_data_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_uni(ngx_connection_t *c,
    ngx_http_v3_parse_uni_t *st, ngx_buf_t *b);


#endif /* _NGX_HTTP_V3_PARSE_H_INCLUDED_ */
