
#include <ngx_config.h>

#include <ngx_alloc.h>
#include <ngx_array.h>

ngx_array_t *ngx_create_array(ngx_pool_t *p, int n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL)
        return NULL;

    a->elts = ngx_palloc(p, n * size);
    if (a->elts == NULL)
        return NULL;

    a->pool = p;
    a->nelts = 0;
    a->nalloc = n;
    a->size = size;

    return a;
}

void ngx_destroy_array(ngx_array_t *a)
{
    ngx_pool_t *p = a->pool;

    if (a->elts + a->size * a->nalloc == p->last)
        p->last -= a->size * a->nalloc;

    if ((char *) a + sizeof(ngx_array_t) == p->last)
        p->last = (char *) a;
}

void *ngx_push_array(ngx_array_t *a)
{
    void *elt;

    /* array is full */
    if (a->nelts == a->nalloc) {
        ngx_pool_t *p = a->pool;

        /* array allocation is the last in the pool */
        if (a->elts + a->size * a->nelts == p->last
            && (unsigned) (p->end - p->last) >= a->size)
        {
            p->last += a->size;
            a->nalloc++;

        /* allocate new array */
        } else {
            void *new = ngx_palloc(p, 2 * a->nalloc * a->size);
            if (new == NULL)
                return NULL;

            memcpy(new, a->elts, a->nalloc * a->size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}
