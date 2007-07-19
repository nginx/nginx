
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
    p->current = p;
    p->chain = NULL;
    p->next = NULL;
    p->large = NULL;
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
    ngx_pool_t        *p, *n, *current;
    ngx_pool_large_t  *large;

    if (size <= (size_t) NGX_MAX_ALLOC_FROM_POOL
        && size <= (size_t) (pool->end - (u_char *) pool)
                   - (size_t) ngx_align_ptr(sizeof(ngx_pool_t), NGX_ALIGNMENT))
    {
        p = pool->current;
        current = p;

        for ( ;; ) {

#if (NGX_HAVE_NONALIGNED)

            /*
             * allow non-aligned memory blocks for small allocations (1, 2,
             * or 3 bytes) and for odd length strings (struct's have aligned
             * size)
             */

            if (size < sizeof(int) || (size & 1)) {
                m = p->last;

            } else
#endif

            {
                m = ngx_align_ptr(p->last, NGX_ALIGNMENT);
            }

            if ((size_t) (p->end - m) >= size) {
                p->last = m + size;

                return m;
            }

            if ((size_t) (p->end - m) < NGX_ALIGNMENT) {
                current = p->next;
            }

            if (p->next == NULL) {
                break;
            }

            p = p->next;
            pool->current = current;
        }

        /* allocate a new pool block */

        n = ngx_create_pool((size_t) (p->end - (u_char *) p), p->log);
        if (n == NULL) {
            return NULL;
        }

        pool->current = current ? current : n;

        p->next = n;
        m = ngx_align_ptr(n->last, NGX_ALIGNMENT);
        n->last = m + size;

        return m;
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

    large = ngx_palloc(pool, sizeof(ngx_pool_large_t));
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

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
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "run cleanup: %p, fd:%d",
                   c, c->fd);

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


void
ngx_pool_delete_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_err_t  err;

    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, c->log, 0, "run cleanup: %p, fd:%d %s",
                   c, c->fd, c->name);

    if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                          ngx_delete_file_n " \"%s\" failed", c->name);
        }
    }

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
