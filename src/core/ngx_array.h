#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>

#include <ngx_alloc.h>

typedef struct {
    char       *elts;
    int         nelts;
    size_t      size;
    int         nalloc;
    ngx_pool_t *pool;
} ngx_array_t;


ngx_array_t *ngx_create_array(ngx_pool_t *p, int n, size_t size);
void ngx_destroy_array(ngx_array_t *a);
void *ngx_push_array(ngx_array_t *a);


#define ngx_init_array(a, p, n, s, rc)                                       \
    ngx_test_null(a.elts, ngx_palloc(p, n * s), rc);                         \
    a.nelts = 0; a.size = s; a.nalloc = n; a.pool = p;


#endif /* _NGX_ARRAY_H_INCLUDED_ */
