
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static int ngx_event_busy_lock_look_cachable(ngx_event_busy_lock_t *bl,
                                             ngx_event_busy_lock_ctx_t *ctx);
static void ngx_event_busy_lock_handler(ngx_event_t *ev);
static void ngx_event_busy_lock_posted_handler(ngx_event_t *ev);


/*
 * NGX_OK:     the busy lock is held
 * NGX_AGAIN:  the all busy locks are held but we will wait the specified time
 * NGX_BUSY:   ctx->timer == 0: there are many the busy locks
 *             ctx->timer != 0: there are many the waiting locks
 * NGX_ERROR:  an error occured while the mutex locking
 */

ngx_int_t ngx_event_busy_lock(ngx_event_busy_lock_t *bl,
                              ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }

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

        if (bl->events) {
            bl->last->next = ctx;

        } else {
            bl->events = ctx;
        }

        bl->last = ctx;

        rc = NGX_AGAIN;

    } else {
        rc = NGX_BUSY;
    }

    ngx_mutex_unlock(bl->mutex);

    return rc;
}


ngx_int_t ngx_event_busy_lock_cachable(ngx_event_busy_lock_t *bl,
                                       ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }

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

    ngx_mutex_unlock(bl->mutex);

    return rc;
}


ngx_int_t ngx_event_busy_unlock(ngx_event_busy_lock_t *bl,
                                ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_event_t                *ev;
    ngx_event_busy_lock_ctx_t  *wakeup;

    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (bl->events) {
        wakeup = bl->events;
        bl->events = bl->events->next;

    } else {
        wakeup = NULL;
        bl->busy--;
    }

    /*
     * MP: all ctx's and their queue must be in shared memory,
     *     each ctx has pid to wake up
     */

    if (wakeup == NULL) {
        ngx_mutex_unlock(bl->mutex);
        return NGX_OK;
    }

    if (ctx->md5) {
        for (wakeup = bl->events; wakeup; wakeup = wakeup->next) {
            if (wakeup->md5 == NULL || wakeup->slot != ctx->slot) {
                continue;
            }

            wakeup->handler = ngx_event_busy_lock_posted_handler;
            wakeup->cache_updated = 1;

            ev = wakeup->event;

            if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_post_event(ev);

            ngx_mutex_unlock(ngx_posted_events_mutex);
        }

        ngx_mutex_unlock(bl->mutex);

    } else {
        bl->waiting--;

        ngx_mutex_unlock(bl->mutex);

        wakeup->handler = ngx_event_busy_lock_posted_handler;
        wakeup->locked = 1;

        ev = wakeup->event;

        if (ev->timer_set) {
            ngx_del_timer(ev);
        }

        if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
            return NGX_ERROR;
        }

        ngx_post_event(ev);

        ngx_mutex_unlock(ngx_posted_events_mutex);
    }

    return NGX_OK;
}


ngx_int_t ngx_event_busy_lock_cancel(ngx_event_busy_lock_t *bl,
                                     ngx_event_busy_lock_ctx_t *ctx)
{
    ngx_event_busy_lock_ctx_t  *c, *p;

    if (ngx_mutex_lock(bl->mutex) == NGX_ERROR) {
        return NGX_ERROR;
    }

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

    ngx_mutex_unlock(bl->mutex);

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
                ctx->waiting = 1;
                ctx->slot = i;
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
    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        return;
    }

    ngx_post_event(ev);

    ngx_mutex_unlock(ngx_posted_events_mutex);

    ev->event_handler = ngx_event_busy_lock_posted_handler;
}


static void ngx_event_busy_lock_posted_handler(ngx_event_t *ev)
{
    ngx_event_busy_lock_ctx_t  *ctx;

    ctx = ev->data;
    ctx->handler(ev);
}
