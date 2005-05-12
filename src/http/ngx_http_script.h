
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
    ngx_http_variable_value_t      *sp;

    ngx_str_t                       buf;
    ngx_str_t                      *line;

    /* the start of the rewritten arguments */
    u_char                         *args;

    unsigned                        skip:1;
    unsigned                        quote:1;
    unsigned                        log:1;

    int                            *captures;

    ngx_int_t                       status;
    ngx_http_request_t             *request;
} ngx_http_script_engine_t;


typedef struct {
    ngx_conf_t                     *cf;
    ngx_str_t                      *source;
    ngx_array_t                   **lengths;
    ngx_array_t                   **values;

    ngx_uint_t                      variables;
    ngx_uint_t                      ncaptures;
    ngx_uint_t                      size;

    void                           *main;

    unsigned                        compile_args:1;
    unsigned                        compile_null:1;
    unsigned                        complete_lengths:1;
    unsigned                        complete_values:1;

    unsigned                        args:1;
} ngx_http_script_compile_t;


typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
typedef size_t (*ngx_http_script_len_code_pt) (ngx_http_script_engine_t *e);


typedef struct {
    ngx_http_script_code_pt         code;
    uintptr_t                       len;
} ngx_http_script_copy_code_t;


typedef struct {
    ngx_http_script_code_pt         code;
    uintptr_t                       index;
} ngx_http_script_var_code_t;


typedef struct {
    ngx_http_script_code_pt          code;
    uintptr_t                        n;
} ngx_http_script_copy_capture_code_t;


typedef struct {
    ngx_http_script_code_pt          code;
    ngx_regex_t                     *regex;
    ngx_array_t                     *lengths;
    uintptr_t                        size;
    uintptr_t                        ncaptures;
    uintptr_t                        status;
    uintptr_t                        next;

    uintptr_t                        test:1;
    uintptr_t                        uri:1;
    uintptr_t                        args:1;

    /* add the r->args to the new arguments */
    uintptr_t                        add_args:1;
    
    uintptr_t                        redirect:1;
    uintptr_t                        break_cycle:1;

    ngx_str_t                        name;
} ngx_http_script_regex_code_t;


typedef struct {
    ngx_http_script_code_pt          code;

    uintptr_t                        uri:1;
    uintptr_t                        args:1;

    /* add the r->args to the new arguments */
    uintptr_t                        add_args:1;

    uintptr_t                        redirect:1;
} ngx_http_script_regex_end_code_t;


typedef struct {
    ngx_http_script_code_pt          code;
    uintptr_t                        status;
    uintptr_t                        null;
} ngx_http_script_return_code_t;


typedef struct {
    ngx_http_script_code_pt          code;
    uintptr_t                        next;
    void                           **loc_conf;
} ngx_http_script_if_code_t;


typedef struct {
    ngx_http_script_code_pt          code;
    uintptr_t                        value;
    uintptr_t                        text_len;
    uintptr_t                        text_data;
} ngx_http_script_value_code_t;


ngx_uint_t ngx_http_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_http_script_compile(ngx_http_script_compile_t *sc);

void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
    size_t size);
void *ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_http_script_copy_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_var_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
void ngx_http_script_regex_end_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
void ngx_http_script_start_args_code(ngx_http_script_engine_t *e);
void ngx_http_script_return_code(ngx_http_script_engine_t *e);
void ngx_http_script_if_code(ngx_http_script_engine_t *e);
void ngx_http_script_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_set_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_nop_code(ngx_http_script_engine_t *e);


#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
