
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_TABLE_H_INCLUDED_
#define _NGX_TABLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_array_t  ngx_table_t;

typedef struct {
    ngx_str_t  key;
    ngx_str_t  value;
} ngx_table_elt_t;


#define ngx_create_table(p, n)  ngx_create_array(p, n, 2 * sizeof(ngx_str_t))
#define ngx_push_table(t)       ngx_push_array(t)


#endif /* _NGX_TABLE_H_INCLUDED_ */
