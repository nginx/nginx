
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_REGEX_H_INCLUDED_
#define _NGX_REGEX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <pcre.h>


#define NGX_REGEX_NO_MATCHED  -1000

#define NGX_REGEX_CASELESS    PCRE_CASELESS

typedef pcre  ngx_regex_t;

void ngx_regex_init(void);
ngx_regex_t *ngx_regex_compile(ngx_str_t *pattern, ngx_int_t options,
    ngx_pool_t *pool, ngx_str_t *err);
ngx_int_t ngx_regex_capture_count(ngx_regex_t *re);
ngx_int_t ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures,
    ngx_int_t size);

#define ngx_regex_exec_n           "pcre_exec()"
#define ngx_regex_capture_count_n  "pcre_fullinfo()"


#endif /* _NGX_REGEX_H_INCLUDED_ */
