
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef u_char *(*ngx_http_script_code_pt) (ngx_http_request_t *r,
                                            u_char *buf, void *data);

typedef struct ngx_http_script_code_s {
    size_t                   data_len;
    size_t                   code_len;
    ngx_http_script_code_pt  code;
} ngx_http_script_code_t;


#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
