
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


struct ngx_array_s {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *pool;
};


ngx_array_t *ngx_create_array(ngx_pool_t *p, ngx_uint_t n, size_t size);
void ngx_destroy_array(ngx_array_t *a);
void *ngx_push_array(ngx_array_t *a);


ngx_inline static ngx_int_t ngx_array_init(ngx_array_t *array, ngx_pool_t *pool,
                                           ngx_uint_t n, size_t size)
{
    if (!(array->elts = ngx_palloc(pool, n * size))) {
        return NGX_ERROR;
    }

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    return NGX_OK;
}



#define ngx_init_array(a, p, n, s, rc)                                       \
    ngx_test_null(a.elts, ngx_palloc(p, n * s), rc);                         \
    a.nelts = 0; a.size = s; a.nalloc = n; a.pool = p;

#define ngx_array_create  ngx_create_array
#define ngx_array_push    ngx_push_array


#endif /* _NGX_ARRAY_H_INCLUDED_ */
