
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void        **buckets;
    ngx_uint_t    hash_size;

    ngx_uint_t    max_size;
    ngx_uint_t    bucket_limit;
    size_t        bucket_size;
    char         *name;
    ngx_uint_t    min_buckets;
} ngx_hash_t;


typedef struct {
    ngx_uint_t  hash;
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_table_elt_t;


ngx_int_t ngx_hash_init(ngx_hash_t *hash, ngx_pool_t *pool, void *names,
    ngx_uint_t nelts);


#endif /* _NGX_HASH_H_INCLUDED_ */
