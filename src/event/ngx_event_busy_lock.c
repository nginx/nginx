
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/*
 * TODO: eliminate mutex and use atomic_xchg():
 *       ev->next = ev; ngx_atomic_xchg(ngx_posted_events, ev->next);
 *       in ngx_event_busy_unlock() and ngx_event_busy_lock_handler()
 */


static int ngx_event_busy_lock_look_cachable(ngx_event_busy_lock_t *bl,
                                             ngx_event_busy_lock_ctx_t *ctx);
static void ngx_event_busy_lock_handler(ngx_event_t *ev);
static void ngx_event_busy_lock_posted_handler(ngx_event_t *ev);


/*
 * NGX_OK:     the busy lock is held
 * NGX_BUSY:   there are many the busy locks or many the waiting locks
 * NGX_AGAIN:  the all busy locks are held but we will wait the specified time
 * NGX_ERROR:  there was error while the mutex locking
 */

ngx_int_t ngx_event_busy_lock(ngx_event_busy_lock_t *bl,
                              ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_int_t  rc;

#if (NGX_THREADS)
    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->event->log, 0,
                   "event busy lock: b:%d mb:%d",
                   bl->busy, bl->max_busy);

    if (bl->busy < bl->max_busy) {
        bl->busy++;
        rc = NGX_OK;

    } else if (ctx->timer && bl->waiting < bl->max_waiting) {
        bl->waiting++;
        ngx_add_timer(ctx->event, ctx->timer);
        ctx->event->event_handler = ngx_event_busy_lock_handler;

        if (bl->events == NULL) {
            bl->events = ctx;
        } else {
            bl->last->next = ctx;
        }
        bl->last = ctx;

        rc = NGX_AGAIN;

    } else {
        rc = NGX_BUSY;
    }

#if (NGX_THREADS)
    ngx_mutex_unlock(bl->mutex);
#endif

    return rc;
}


ngx_int_t ngx_event_busy_lock_cachable(ngx_event_busy_lock_t *bl,
                                       ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_int_t  rc;

#if (NGX_THREADS)
    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }
#endif

    rc = ngx_event_busy_lock_look_cachable(bl, ctx);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ctx->event->log, 0,
                   "event busy lock: %d w:%d mw:%d",
                   rc, bl->waiting, bl->max_waiting);

    /*
     * NGX_OK:     no the same request, there is free slot and we locked it
     * NGX_BUSY:   no the same request and there is no free slot
     * NGX_AGAIN:  the same request is processing
     */

    if (rc == NGX_AGAIN) {

        if (ctx->timer && bl->waiting < bl->max_waiting) {
            bl->waiting++;
            ngx_add_timer(ctx->event, ctx->timer);
            ctx->event->event_handler = ngx_event_busy_lock_handler;

            if (bl->events == NULL) {
                bl->events = ctx;
            } else {
                bl->last->next = ctx;
            }
            bl->last = ctx;

        } else {
            rc = NGX_BUSY;
        }
    }

#if (NGX_THREADS)
    ngx_mutex_unlock(bl->mutex);
#endif

    return rc;
}


ngx_int_t ngx_event_busy_unlock(ngx_event_busy_lock_t *bl,
                                ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_event_t                *ev;
    ngx_event_busy_lock_ctx_t  *wakeup;

#if (NGX_THREADS)
    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }
#endif

    if (bl->events) {
        wakeup = bl->events;
        bl->events = bl->events->next;

    } else {
        wakeup = NULL;
        bl->busy--;
    }

    /*
     * MP:
     * nocachable (bl->md5 == NULL): ngx_shared_mutex_unlock(mutex, !wakeup)
     * cachable (bl->md5): ???
     */

    if (wakeup == NULL) {
#if (NGX_THREADS)
        ngx_mutex_unlock(bl->mutex);
#endif
        return NGX_OK;
    }

    if (ctx->md5) {
        for (wakeup = bl->events; wakeup; wakeup = wakeup->next) {
            if (wakeup->md5 == NULL) {
                continue;
            }

            if (ngx_memcmp(ctx->md5, wakeup->md5, 16) != 0) {
                continue;
            }
            
            wakeup->handler = ngx_event_busy_lock_posted_handler;
            wakeup->cache_updated = 1;

            ev = wakeup->event;

#if (NGX_THREADS)
            if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                return NGX_ERROR;
            }
#endif

            ev->next = (ngx_event_t *) ngx_posted_events;
            ngx_posted_events = ev;

#if (NGX_THREADS)
            ngx_mutex_unlock(ngx_posted_events_mutex);
#endif
        }

#if (NGX_THREADS)
        ngx_mutex_unlock(bl->mutex);
#endif

    } else {
        bl->waiting--;

#if (NGX_THREADS)
        ngx_mutex_unlock(bl->mutex);
#endif

        wakeup->handler = ngx_event_busy_lock_posted_handler;
        wakeup->locked = 1;

        ev = wakeup->event;

        if (ev->timer_set) {
            ngx_del_timer(ev);
        }

#if (NGX_THREADS)
        if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
            return NGX_ERROR;
        }
#endif

        ev->next = (ngx_event_t *) ngx_posted_events;
        ngx_posted_events = ev;

#if (NGX_THREADS)
        ngx_mutex_unlock(ngx_posted_events_mutex);
#endif
    }

    return NGX_OK;
}


ngx_int_t ngx_event_busy_lock_cancel(ngx_event_busy_lock_t *bl,
                                     ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_event_busy_lock_ctx_t  *c, *p;

#if (NGX_THREADS)
    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }
#endif

    bl->waiting--;

    if (ctx == bl->events) {
        bl->events = ctx->next;

    } else {
        p = bl->events;
        for (c = bl->events->next; c; c = c->next) {
            if (c == ctx) {
                p->next = ctx->next;
                break;
            }
            p = c;
        }
    }

#if (NGX_THREADS)
    ngx_mutex_unlock(bl->mutex);
#endif

    return NGX_OK;
}


static int ngx_event_busy_lock_look_cachable(ngx_event_busy_lock_t *bl,
                                             ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_int_t    free;
    ngx_uint_t   i, bit, cachable, mask;

    bit = 0;
    cachable = 0;
    free = -1;

#if (NGX_SUPPRESS_WARN)
    mask = 0;
#endif

    for (i = 0; i < bl->max_busy; i++) {

        if ((bit & 7) == 0) {
            mask = bl->md5_mask[i / 8];
        }

        if (mask & 1) {
            if (ngx_memcmp(&bl->md5[i * 16], ctx->md5, 16) == 0) {
                return NGX_AGAIN;
            }
            cachable++;

        } else if (free == -1) {
            free = i;
        }

        if (cachable == bl->cachable) {
            if (free == -1 && cachable < bl->max_busy) {
                free = i + 1;
            }

            break;
        }

        mask >>= 1;
        bit++;
    }

    if (free == -1) {
        return NGX_BUSY;
    }

#if 0
    if (bl->busy == bl->max_busy) {
        return NGX_BUSY;
    }
#endif

    ngx_memcpy(&bl->md5[free * 16], ctx->md5, 16);
    bl->md5_mask[free / 8] |= 1 << (free & 7);
    ctx->slot = free;

    bl->cachable++;
    bl->busy++;

    return NGX_OK;
}


static void ngx_event_busy_lock_handler(ngx_event_t *ev)
{
    ev->event_handler = ngx_event_busy_lock_posted_handler;

#if (NGX_THREADS)
    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        return;
    }
#endif

    ev->next = (ngx_event_t *) ngx_posted_events;
    ngx_posted_events = ev;

#if (NGX_THREADS)
    ngx_mutex_unlock(ngx_posted_events_mutex);
#endif
}


static void ngx_event_busy_lock_posted_handler(ngx_event_t *ev)
{
    ngx_event_busy_lock_ctx_t  *ctx;

    ctx = ev->data;
    ctx->handler(ev);
}
