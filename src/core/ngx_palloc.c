
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;

    p = ngx_alloc(size, log);
    if (p == NULL) {
        return NULL;
    }

    p->last = (u_char *) p + sizeof(ngx_pool_t);
    p->end = (u_char *) p + size;
    p->next = NULL;
    p->large = NULL;
    p->chain = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}


void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            c->handler(c->data);
        }
    }

    for (l = pool->large; l; l = l->next) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);

        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we can not use this log while the free()ing the pool
     */

    for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->end - p->last);

        if (n == NULL) {
            break;
        }
    }

#endif

    for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    u_char            *m;
    ngx_pool_t        *p, *n;
    ngx_pool_large_t  *large, *last;

    if (size <= (size_t) NGX_MAX_ALLOC_FROM_POOL
        && size <= (size_t) (pool->end - (u_char *) pool)
                                     - (size_t) ngx_align(sizeof(ngx_pool_t)))
    {
        for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
            m = ngx_align(p->last);

            if ((size_t) (p->end - m) >= size) {
                p->last = m + size;

                return m;
            }

            if (n == NULL) {
                break;
            }
        }

        /* allocate a new pool block */

        n = ngx_create_pool((size_t) (p->end - (u_char *) p), p->log);
        if (n == NULL) {
            return NULL;
        }

        p->next = n;
        m = ngx_align(n->last);
        n->last = m + size;

        return m;
    }

    /* allocate a large block */

    large = NULL;
    last = NULL;

    if (pool->large) {
        for (last = pool->large; /* void */ ; last = last->next) {
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
        large = ngx_palloc(pool, sizeof(ngx_pool_large_t));
        if (large == NULL) {
            return NULL;
        }

        large->next = NULL;
    }

#if 0
    p = ngx_memalign(ngx_pagesize, size, pool->log);
    if (p == NULL) {
        return NULL;
    }
#else
    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }
#endif

    if (pool->large == NULL) {
        pool->large = large;

    } else if (last) {
        last->next = large;
    }

    large->alloc = p;

    return p;
}


ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, ngx_pool_cleanup_pt handler, void *data)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    c->handler = handler;
    c->data = data;
    c->next = p->cleanup;

    p->cleanup = c;

    return c;
}


void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
