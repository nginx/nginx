
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


typedef ngx_int_t (*ngx_json_handler_pt)(ngx_json_event_e event,
    ngx_str_t *token, void *data);


ngx_int_t ngx_json_parse(ngx_pool_t *pool, ngx_str_t *json,
    ngx_uint_t max_depth, ngx_json_handler_pt handler, void *data);


#endif /* _NGX_JSON_PARSE_H_INCLUDED_ */
