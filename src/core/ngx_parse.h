
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_PARSE_H_INCLUDED_
#define _NGX_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PARSE_LARGE_TIME  -2


ngx_int_t ngx_parse_size(ngx_str_t *line);
ngx_int_t ngx_parse_time(ngx_str_t *line, ngx_int_t sec);


#endif /* _NGX_PARSE_H_INCLUDED_ */
