
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_TABLE_H_INCLUDED_
#define _NGX_HTTP_V3_TABLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* static table indices */
#define NGX_HTTP_V3_HEADER_AUTHORITY                 0
#define NGX_HTTP_V3_HEADER_PATH_ROOT                 1
#define NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO       4
#define NGX_HTTP_V3_HEADER_DATE                      6
#define NGX_HTTP_V3_HEADER_LAST_MODIFIED             10
#define NGX_HTTP_V3_HEADER_LOCATION                  12
#define NGX_HTTP_V3_HEADER_METHOD_GET                17
#define NGX_HTTP_V3_HEADER_METHOD_HEAD               18
#define NGX_HTTP_V3_HEADER_METHOD_POST               20
#define NGX_HTTP_V3_HEADER_METHOD_PUT                21
#define NGX_HTTP_V3_HEADER_SCHEME_HTTP               22
#define NGX_HTTP_V3_HEADER_SCHEME_HTTPS              23
#define NGX_HTTP_V3_HEADER_STATUS_103                24
#define NGX_HTTP_V3_HEADER_STATUS_200                25
#define NGX_HTTP_V3_HEADER_ACCEPT_ENCODING           31
#define NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN   53
#define NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING      59
#define NGX_HTTP_V3_HEADER_ACCEPT_LANGUAGE           72
#define NGX_HTTP_V3_HEADER_SERVER                    92
#define NGX_HTTP_V3_HEADER_USER_AGENT                95


typedef struct {
    ngx_str_t                     name;
    ngx_str_t                     value;
} ngx_http_v3_field_t;


typedef struct {
    ngx_http_v3_field_t         **elts;
    ngx_uint_t                    nelts;
    ngx_uint_t                    base;
    size_t                        size;
    size_t                        capacity;
    uint64_t                      insert_count;
    uint64_t                      ack_insert_count;
    ngx_event_t                   send_insert_count;
} ngx_http_v3_dynamic_table_t;


void ngx_http_v3_inc_insert_count_handler(ngx_event_t *ev);
void ngx_http_v3_cleanup_table(ngx_http_v3_session_t *h3c);
ngx_int_t ngx_http_v3_ref_insert(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value);
ngx_int_t ngx_http_v3_insert(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
ngx_int_t ngx_http_v3_set_capacity(ngx_connection_t *c, ngx_uint_t capacity);
ngx_int_t ngx_http_v3_duplicate(ngx_connection_t *c, ngx_uint_t index);
ngx_int_t ngx_http_v3_ack_section(ngx_connection_t *c, ngx_uint_t stream_id);
ngx_int_t ngx_http_v3_inc_insert_count(ngx_connection_t *c, ngx_uint_t inc);
ngx_int_t ngx_http_v3_lookup_static(ngx_connection_t *c, ngx_uint_t index,
    ngx_str_t *name, ngx_str_t *value);
ngx_int_t ngx_http_v3_lookup(ngx_connection_t *c, ngx_uint_t index,
    ngx_str_t *name, ngx_str_t *value);
ngx_int_t ngx_http_v3_decode_insert_count(ngx_connection_t *c,
    ngx_uint_t *insert_count);
ngx_int_t ngx_http_v3_check_insert_count(ngx_connection_t *c,
    ngx_uint_t insert_count);
void ngx_http_v3_ack_insert_count(ngx_connection_t *c, uint64_t insert_count);
ngx_int_t ngx_http_v3_set_param(ngx_connection_t *c, uint64_t id,
    uint64_t value);


#endif /* _NGX_HTTP_V3_TABLE_H_INCLUDED_ */
