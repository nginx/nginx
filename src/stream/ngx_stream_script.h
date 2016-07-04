
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_SCRIPT_H_INCLUDED_
#define _NGX_STREAM_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    u_char                       *ip;
    u_char                       *pos;
    ngx_stream_variable_value_t  *sp;

    ngx_str_t                     buf;
    ngx_str_t                     line;

    unsigned                      flushed:1;
    unsigned                      skip:1;

    ngx_stream_session_t         *session;
} ngx_stream_script_engine_t;


typedef struct {
    ngx_conf_t                   *cf;
    ngx_str_t                    *source;

    ngx_array_t                 **flushes;
    ngx_array_t                 **lengths;
    ngx_array_t                 **values;

    ngx_uint_t                    variables;
    ngx_uint_t                    ncaptures;
    ngx_uint_t                    size;

    void                         *main;

    unsigned                      complete_lengths:1;
    unsigned                      complete_values:1;
    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} ngx_stream_script_compile_t;


typedef struct {
    ngx_str_t                     value;
    ngx_uint_t                   *flushes;
    void                         *lengths;
    void                         *values;
} ngx_stream_complex_value_t;


typedef struct {
    ngx_conf_t                   *cf;
    ngx_str_t                    *value;
    ngx_stream_complex_value_t   *complex_value;

    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} ngx_stream_compile_complex_value_t;


typedef void (*ngx_stream_script_code_pt) (ngx_stream_script_engine_t *e);
typedef size_t (*ngx_stream_script_len_code_pt) (ngx_stream_script_engine_t *e);


typedef struct {
    ngx_stream_script_code_pt     code;
    uintptr_t                     len;
} ngx_stream_script_copy_code_t;


typedef struct {
    ngx_stream_script_code_pt     code;
    uintptr_t                     index;
} ngx_stream_script_var_code_t;


typedef struct {
    ngx_stream_script_code_pt     code;
    uintptr_t                     n;
} ngx_stream_script_copy_capture_code_t;


typedef struct {
    ngx_stream_script_code_pt     code;
    uintptr_t                     conf_prefix;
} ngx_stream_script_full_name_code_t;


void ngx_stream_script_flush_complex_value(ngx_stream_session_t *s,
    ngx_stream_complex_value_t *val);
ngx_int_t ngx_stream_complex_value(ngx_stream_session_t *s,
    ngx_stream_complex_value_t *val, ngx_str_t *value);
ngx_int_t ngx_stream_compile_complex_value(
    ngx_stream_compile_complex_value_t *ccv);
char *ngx_stream_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


ngx_uint_t ngx_stream_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_stream_script_compile(ngx_stream_script_compile_t *sc);

void *ngx_stream_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_stream_script_copy_len_code(ngx_stream_script_engine_t *e);
void ngx_stream_script_copy_code(ngx_stream_script_engine_t *e);
size_t ngx_stream_script_copy_var_len_code(ngx_stream_script_engine_t *e);
void ngx_stream_script_copy_var_code(ngx_stream_script_engine_t *e);
size_t ngx_stream_script_copy_capture_len_code(ngx_stream_script_engine_t *e);
void ngx_stream_script_copy_capture_code(ngx_stream_script_engine_t *e);

#endif /* _NGX_STREAM_SCRIPT_H_INCLUDED_ */
