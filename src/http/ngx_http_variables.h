
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


#define NGX_HTTP_VAR_NOT_FOUND  (ngx_http_variable_value_t *) -1


typedef struct {
    ngx_uint_t                     value;
    ngx_str_t                      text;
} ngx_http_variable_value_t;

typedef struct ngx_http_variable_s  ngx_http_variable_t;

typedef ngx_http_variable_value_t *
    (*ngx_http_get_variable_pt) (ngx_http_request_t *r, uintptr_t data);


#define NGX_HTTP_VAR_CHANGABLE   1
#define NGX_HTTP_VAR_NOCACHABLE  2
#define NGX_HTTP_VAR_INDEXED     4


struct ngx_http_variable_s {
    ngx_str_t                  name;   /* must be first to build the hash */
    ngx_http_get_variable_pt   handler;
    uintptr_t                  data;
    ngx_uint_t                 flags;
    ngx_uint_t                 index;
};


ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
    ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
    ngx_str_t *name);

ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
