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


#endif /* _NGX_ARRAY_H_INCLUDED_ */
