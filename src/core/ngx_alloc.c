
#include <ngx_config.h>

#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_string.h>
#include <ngx_alloc.h>


void *ngx_alloc(size_t size, ngx_log_t *log)
{
    void *p;

    p = malloc(size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "malloc() %d bytes failed", size);
    }

#if (NGX_DEBUG_ALLOC)
    ngx_log_debug(log, "malloc: %08x:%d" _ p _ size);
#endif

    return p;
}

void *ngx_calloc(size_t size, ngx_log_t *log)
{
    void *p;

    p = ngx_alloc(size, log);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t *p;

    ngx_test_null(p, ngx_alloc(size, log), NULL);

    p->last = (char *) p + sizeof(ngx_pool_t);
    p->end = (char *) p + size;
    p->next = NULL;
    p->large = NULL;
    p->log = log;

    return p;
}

void ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t        *p, *n;
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
#if (NGX_DEBUG_ALLOC)
        ngx_log_debug(pool->log, "free: %08x" _ l->alloc);
#endif
        free(l->alloc);
    }

    for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
#if (NGX_DEBUG_ALLOC)
        ngx_log_debug(pool->log, "free: %08x" _ p);
#endif
        free(p);

        if (n == NULL) {
            break;
        }
    }
}

void *ngx_palloc(ngx_pool_t *pool, size_t size)
{
    void              *m;
    ngx_pool_t        *p, *n;
    ngx_pool_large_t  *large, *last;

    if (size <= NGX_MAX_ALLOC_FROM_POOL) {

        for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
            if ((size_t) (p->end - ngx_align(p->last)) >= size) {
                m = ngx_align(p->last);
                p->last = ngx_align(p->last);
                p->last += size ;

                return m;
            }

            if (n == NULL) {
                break;
            }
        }

        /* alloc new pool block */
        ngx_test_null(n, ngx_create_pool(p->end - (char *) p, p->log), NULL);
        p->next = n;
        m = n->last;
        n->last += size;
        return m;

    /* alloc large block */
    } else {
        large = NULL;
        last = NULL;

        if (pool->large) {
            for (last = pool->large; /* void */; last = last->next) {
                if (last->alloc == NULL) {
                    large = last;
                    last = NULL;
                    break;
                }

                if (last->next == NULL) {
                    break;
                }
            }
        }

        if (large == NULL) {
            ngx_test_null(large, ngx_palloc(pool, sizeof(ngx_pool_large_t)),
                          NULL);
            large->next = NULL;
        }

        ngx_test_null(p, ngx_alloc(size, pool->log), NULL);

        if (pool->large == NULL) {
            pool->large = large;

        } else if (last) {
            last->next = large;
        }

        large->alloc = p;

        return p;
    }
}

void *ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}
