
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_LOG_HANDLER_H_INCLUDED_
#define _NGX_HTTP_LOG_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef u_char *(*ngx_http_log_op_pt) (ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data);

#define NGX_HTTP_LOG_COPY_SHORT  (ngx_http_log_op_pt) 0
#define NGX_HTTP_LOG_COPY_LONG   (ngx_http_log_op_pt) -1

#define NGX_HTTP_LOG_ARG         (u_int) -1


typedef struct {
    size_t               len;
    ngx_http_log_op_pt   op;
    uintptr_t            data;
} ngx_http_log_op_t;


typedef struct {
    ngx_str_t            name;
    ngx_array_t         *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;


typedef struct {
    ngx_str_t            name;
    size_t               len;
    ngx_http_log_op_pt   op;
} ngx_http_log_op_name_t;


typedef struct {
    ngx_array_t          formats;    /* array of ngx_http_log_fmt_t */
} ngx_http_log_main_conf_t;


typedef struct {
    ngx_open_file_t     *file;
    ngx_array_t         *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_t;


typedef struct {
    ngx_array_t         *logs;       /* array of ngx_http_log_t */
    ngx_uint_t           off;        /* unsigned  off:1 */
} ngx_http_log_loc_conf_t;


extern ngx_http_log_op_name_t ngx_http_log_fmt_ops[];


#endif /* _NGX_HTTP_LOG_HANDLER_H_INCLUDED_ */
