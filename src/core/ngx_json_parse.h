
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_JSON_PARSE_H_INCLUDED_
#define _NGX_JSON_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_json_unescape.h>


#define NGX_JSON_SKIP                    -7
#define NGX_JSON_DEFAULT_MAX_DEPTH       64


typedef enum {
    NGX_JSON_OBJECT_OPEN = 0,
    NGX_JSON_OBJECT_CLOSE,
    NGX_JSON_ARRAY_OPEN,
    NGX_JSON_ARRAY_CLOSE,
    NGX_JSON_KEY,
    NGX_JSON_VALUE_STRING,
    NGX_JSON_VALUE_NUMBER,
    NGX_JSON_VALUE_BOOL,
    NGX_JSON_VALUE_NULL
} ngx_json_event_e;


typedef enum {
    ngx_json_start = 0,
    ngx_json_done,
    ngx_json_object,
    ngx_json_object_next,
    ngx_json_object_name_separator,
    ngx_json_value,
    ngx_json_object_value_separator,
    ngx_json_array_value_separator,
    ngx_json_array,
    ngx_json_string,
    ngx_json_number_minus,
    ngx_json_number_int,
    ngx_json_number_int_zero,
    ngx_json_number_frac,
    ngx_json_number_frac_digit,
    ngx_json_number_exp,
    ngx_json_number_exp_plusminus,
    ngx_json_number_exp_digit,
    ngx_json_escaped,
    ngx_json_escaped_hex,       /* first \uXXXX: reading the four hex digits */
    ngx_json_surrogate_start,   /* expect '\' beginning the low surrogate */
    ngx_json_surrogate_u,       /* expect 'u' of the low surrogate */
    ngx_json_surrogate_hex,     /* low \uXXXX: reading the four hex digits */
    ngx_json_true_t,
    ngx_json_true_tr,
    ngx_json_true_tru,
    ngx_json_false_f,
    ngx_json_false_fa,
    ngx_json_false_fal,
    ngx_json_false_fals,
    ngx_json_null_n,
    ngx_json_null_nu,
    ngx_json_null_nul
} ngx_json_state_e;


typedef enum {
    ngx_json_ctx_none = 0,
    ngx_json_ctx_object,
    ngx_json_ctx_array
} ngx_json_container_e;


typedef struct ngx_json_ctx_s  ngx_json_ctx_t;


typedef ngx_int_t (*ngx_json_handler_pt)(ngx_json_ctx_t *ctx,
    ngx_json_event_e event, ngx_str_t *token);


struct ngx_json_ctx_s {
    ngx_json_state_e       state;

    ngx_json_container_e  *stack;
    ngx_uint_t             depth;
    ngx_uint_t             max_depth;

    uint32_t               codepoint;
    ngx_uint_t             hex_left;         /* hex digits still expected */

    ngx_uint_t             skip_until_depth;

    ngx_pool_t            *pool;
    ngx_json_handler_pt    handler;
    void                  *data;

    unsigned               in_key; /* unsigned in_key:1 */
};


void ngx_json_ctx_init(ngx_json_ctx_t *ctx, ngx_pool_t *pool);
ngx_int_t ngx_json_parse_ctx(ngx_json_ctx_t *ctx, u_char *data, size_t len);
ngx_int_t ngx_json_parse(ngx_pool_t *pool, ngx_str_t *json,
    ngx_json_handler_pt handler, void *data);


#endif /* _NGX_JSON_PARSE_H_INCLUDED_ */
