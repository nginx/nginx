
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_char                         *ip;
    u_char                         *pos;
    ngx_http_request_t             *request;
} ngx_http_script_lite_engine_t;


typedef struct {
    ngx_http_script_lite_engine_t   lite;
} ngx_http_script_engine_t;


typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
typedef size_t (*ngx_http_script_len_code_pt)
    (ngx_http_script_lite_engine_t *e);

typedef ngx_int_t (*ngx_http_script_compile_lite_start_pt) (ngx_table_elt_t *h,
    ngx_array_t *lengths, ngx_array_t *values, ngx_uint_t value);
typedef ngx_int_t (*ngx_http_script_compile_lite_end_pt) (ngx_array_t *lengths,
    ngx_array_t *values);


typedef struct {
    ngx_http_script_code_pt         code;
    uintptr_t                       len;
} ngx_http_script_copy_code_t;


typedef struct {
    ngx_http_script_code_pt         code;
    uintptr_t                       index;
} ngx_http_script_var_code_t;


ngx_int_t ngx_http_script_compile_lite(ngx_conf_t *cf, ngx_array_t *sources,
    ngx_array_t **lengths, ngx_array_t **values,
    ngx_http_script_compile_lite_start_pt start,
    ngx_http_script_compile_lite_end_pt end);


static void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
    size_t size);

size_t ngx_http_script_copy_len(ngx_http_script_engine_t *e);
void ngx_http_script_copy(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_var_len(ngx_http_script_engine_t *e);
void ngx_http_script_copy_var(ngx_http_script_engine_t *e);



#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
