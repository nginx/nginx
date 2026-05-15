
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    size_t       size;
    ngx_pool_t  *p;

    p = a->pool;

    if (ngx_array_calc_size(a->nalloc, a->size, &size) == NGX_OK
        && (u_char *) a->elts + size == p->d.last)
    {
        p->d.last -= size;
    }

    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size, alloc;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        if (ngx_array_calc_size(a->nalloc, a->size, &size) != NGX_OK) {
            return NULL;
        }

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && a->size <= (size_t) (p->d.end - p->d.last))
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            if (a->nalloc > (ngx_uint_t) -1 / 2) {
                return NULL;
            }

            if (ngx_array_calc_size(2, size, &alloc) != NGX_OK) {
                return NULL;
            }

            new = ngx_palloc(p, alloc);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    if (ngx_array_calc_size(a->nelts, a->size, &size) != NGX_OK) {
        return NULL;
    }

    elt = (u_char *) a->elts + size;
    a->nelts++;

    return elt;
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size, alloc;
    ngx_uint_t   nelts;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    if (ngx_array_calc_size(n, a->size, &size) != NGX_OK) {
        return NULL;
    }

    nelts = a->nelts + n;

    if (nelts < a->nelts) {
        return NULL;
    }

    if (nelts > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if (ngx_array_calc_size(a->nalloc, a->size, &alloc) != NGX_OK) {
            return NULL;
        }

        if ((u_char *) a->elts + alloc == p->d.last
            && size <= (size_t) (p->d.end - p->d.last))
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = (n >= a->nalloc) ? n : a->nalloc;

            if (nalloc > (ngx_uint_t) -1 / 2) {
                return NULL;
            }

            nalloc *= 2;

            if (ngx_array_calc_size(nalloc, a->size, &alloc) != NGX_OK) {
                return NULL;
            }

            new = ngx_palloc(p, alloc);
            if (new == NULL) {
                return NULL;
            }

            if (ngx_array_calc_size(a->nelts, a->size, &alloc) != NGX_OK) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, alloc);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    if (ngx_array_calc_size(a->nelts, a->size, &size) != NGX_OK) {
        return NULL;
    }

    elt = (u_char *) a->elts + size;
    a->nelts = nelts;

    return elt;
}
