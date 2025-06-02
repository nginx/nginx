
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_PARSE_H_INCLUDED_
#define _NGX_HTTP_V3_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_http_v3_process_insert_count_pt)(void *data,
    ngx_uint_t *insert_count);
typedef ngx_int_t (*ngx_http_v3_process_header_pt)(void *data, ngx_str_t *name,
    ngx_str_t *value, ngx_uint_t index, ngx_uint_t dynamic);

typedef ngx_int_t (*ngx_http_v3_set_param_pt)(void *data, uint64_t id,
    uint64_t value);

typedef ngx_int_t (*ngx_http_v3_ref_insert_pt)(void *data, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value);
typedef ngx_int_t (*ngx_http_v3_insert_pt)(void *data, ngx_str_t *name,
    ngx_str_t *value);
typedef ngx_int_t (*ngx_http_v3_duplicate_pt)(void *data, ngx_uint_t index);
typedef ngx_int_t (*ngx_http_v3_set_capacity_pt)(void *data,
    ngx_uint_t capacity);


typedef ngx_int_t (*ngx_http_v3_ack_section_pt)(void *data,
    ngx_uint_t stream_id);
typedef ngx_int_t (*ngx_http_v3_cancel_stream_pt)(void *data,
    ngx_uint_t stream_id);
typedef ngx_int_t (*ngx_http_v3_inc_insert_count_pt)(void *data,
    ngx_uint_t inc);


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

    ngx_http_v3_set_param_pt        set_param;
    void                           *data;
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
    ngx_uint_t                      max_literal;

    ngx_str_t                       name;
    ngx_str_t                       value;

    ngx_http_v3_parse_prefix_int_t  pint;
    ngx_http_v3_parse_literal_t     literal;

    unsigned                        has_name:1;
    unsigned                        has_value:1;
} ngx_http_v3_parse_field_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_field_t       field;
    ngx_uint_t                      max_literal;
} ngx_http_v3_parse_field_rep_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_uint_t                      base;
    ngx_uint_t                      insert_count;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_field_section_prefix_t  prefix;
    ngx_http_v3_parse_field_rep_t   field_rep;
    ngx_uint_t                      max_literal;

    ngx_http_v3_process_insert_count_pt
                                    process_insert_count;
    ngx_http_v3_process_header_pt   process_header;
    void                           *data;
} ngx_http_v3_parse_headers_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      max_literal;
    ngx_http_v3_parse_field_t       field;
    ngx_http_v3_parse_prefix_int_t  pint;

    ngx_http_v3_ref_insert_pt       ref_insert;
    ngx_http_v3_insert_pt           insert;
    ngx_http_v3_duplicate_pt        duplicate;
    ngx_http_v3_set_capacity_pt     set_capacity;
    void                           *data;
} ngx_http_v3_parse_encoder_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      max_literal;
    ngx_http_v3_parse_prefix_int_t  pint;

    ngx_http_v3_ack_section_pt      ack_section;
    ngx_http_v3_cancel_stream_pt    cancel_stream;
    ngx_http_v3_inc_insert_count_pt
                                    inc_insert_count;
    void                           *data;
} ngx_http_v3_parse_decoder_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_uint_t                      max_literal;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_settings_t    settings;

    ngx_http_v3_set_param_pt        set_param;
    void                           *data;
} ngx_http_v3_parse_control_t;


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

ngx_int_t ngx_http_v3_parse_varlen_int(ngx_connection_t *c,
    ngx_http_v3_parse_varlen_int_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_control(ngx_connection_t *c,
    ngx_http_v3_parse_control_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_encoder(ngx_connection_t *c,
    ngx_http_v3_parse_encoder_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_decoder(ngx_connection_t *c,
    ngx_http_v3_parse_decoder_t *st, ngx_buf_t *b);


#endif /* _NGX_HTTP_V3_PARSE_H_INCLUDED_ */
