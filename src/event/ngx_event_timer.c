
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_THREADS)
ngx_mutex_t  *ngx_event_timer_mutex;
#endif


ngx_thread_volatile ngx_rbtree_t  *ngx_event_timer_rbtree;
ngx_rbtree_t                       ngx_event_timer_sentinel;


ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    if (ngx_event_timer_rbtree) {
#if (NGX_THREADS)
        ngx_event_timer_mutex->log = log;
#endif
        return NGX_OK;
    }

    ngx_event_timer_rbtree = &ngx_event_timer_sentinel;

#if (NGX_THREADS)
    ngx_event_timer_mutex = ngx_mutex_init(log, 0);
    if (ngx_event_timer_mutex == NULL) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


ngx_msec_t
ngx_event_find_timer(void)
{
    ngx_msec_t     timer;
    ngx_rbtree_t  *node;

    if (ngx_event_timer_rbtree == &ngx_event_timer_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    if (ngx_mutex_lock(ngx_event_timer_mutex) == NGX_ERROR) {
        return NGX_TIMER_ERROR;
    }

    node = ngx_rbtree_min((ngx_rbtree_t *) ngx_event_timer_rbtree,
                          &ngx_event_timer_sentinel);

    ngx_mutex_unlock(ngx_event_timer_mutex);

    timer = (ngx_msec_t) node->key - ngx_current_time;

    return timer > 0 ? timer : 0 ;
}


void
ngx_event_expire_timers(void)
{
    ngx_event_t   *ev;
    ngx_rbtree_t  *node;

    for ( ;; ) {

        if (ngx_event_timer_rbtree == &ngx_event_timer_sentinel) {
            return;
        }

        if (ngx_mutex_lock(ngx_event_timer_mutex) == NGX_ERROR) {
            return;
        }

        node = ngx_rbtree_min((ngx_rbtree_t *) ngx_event_timer_rbtree,
                              &ngx_event_timer_sentinel);

        /* node->key <= ngx_current_time */

        if ((ngx_rbtree_key_int_t) node->key
                                      - (ngx_rbtree_key_int_t) ngx_current_time
            <= 0)
        {
            ev = (ngx_event_t *)
                           ((char *) node - offsetof(ngx_event_t, rbtree_key));

#if (NGX_THREADS)

            if (ngx_threaded && ngx_trylock(ev->lock) == 0) {

                /*
                 * We can not change the timer of the event that is been
                 * handling by another thread.  And we can not easy walk
                 * the rbtree to find a next expired timer so we exit the loop.
                 * However it should be rare case when the event that is
                 * been handling has expired timer.
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "event %p is busy in expire timers", ev);
                break;
            }
#endif

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "event timer del: %d: %M",
                           ngx_event_ident(ev->data), ev->rbtree_key);

            ngx_rbtree_delete((ngx_rbtree_t **) &ngx_event_timer_rbtree,
                              &ngx_event_timer_sentinel,
                              (ngx_rbtree_t *) &ev->rbtree_key);

            ngx_mutex_unlock(ngx_event_timer_mutex);

#if (NGX_DEBUG)
            ev->rbtree_left = NULL;
            ev->rbtree_right = NULL;
            ev->rbtree_parent = NULL;
#endif

            ev->timer_set = 0;

#if (NGX_THREADS)
            if (ngx_threaded) {
                if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                    return;
                }

                ev->posted_timedout = 1;
                ngx_post_event(ev);

                ngx_mutex_unlock(ngx_posted_events_mutex);

                ngx_unlock(ev->lock);

                continue;
            }
#endif

            ev->timedout = 1;

            ev->handler(ev);

            continue;
        }

        break;
    }

    ngx_mutex_unlock(ngx_event_timer_mutex);
}
