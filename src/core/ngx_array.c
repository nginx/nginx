
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_array_t *ngx_create_array(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    ngx_test_null(a, ngx_palloc(p, sizeof(ngx_array_t)), NULL);

    ngx_test_null(a->elts, ngx_palloc(p, n * size), NULL);

    a->pool = p;
    a->nelts = 0;
    a->nalloc = n;
    a->size = size;

    return a;
}


void ngx_destroy_array(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    if ((char *) a->elts + a->size * a->nalloc == p->last) {
        p->last -= a->size * a->nalloc;
    }

    if ((char *) a + sizeof(ngx_array_t) == p->last) {
        p->last = (char *) a;
    }
}


void *ngx_push_array(ngx_array_t *a)
{
    void        *elt, *new;
    ngx_pool_t  *p;

    /* array is full */
    if (a->nelts == a->nalloc) {
        p = a->pool;

        /* array allocation is the last in the pool */
        if ((char *) a->elts + a->size * a->nelts == p->last
            && (unsigned) (p->end - p->last) >= a->size)
        {
            p->last += a->size;
            a->nalloc++;

        /* allocate new array */
        } else {
            ngx_test_null(new, ngx_palloc(p, 2 * a->nalloc * a->size), NULL);

            ngx_memcpy(new, a->elts, a->nalloc * a->size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}
