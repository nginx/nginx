
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PRIORITY_H_INCLUDED_
#define _NGX_HTTP_PRIORITY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    unsigned              urgency:3;     /* 0-7, default 3, lower is higher */
    unsigned              incremental:1;
    unsigned              urgency_set:1;
    unsigned              incremental_set:1;
} ngx_http_priority_t;


typedef struct {
    ngx_http_priority_t   client;
    ngx_http_priority_t   server;
    ngx_http_priority_t   effective;
} ngx_http_priority_state_t;


void ngx_http_priority_state_init(ngx_http_priority_state_t *ps);
ngx_int_t ngx_http_priority_parse(ngx_str_t *field, ngx_http_priority_t *p);
void ngx_http_priority_state_update(ngx_http_priority_state_t *ps);


#endif /* _NGX_HTTP_PRIORITY_H_INCLUDED_ */
