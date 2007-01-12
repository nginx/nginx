
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_THREADS)
ngx_mutex_t  *ngx_event_timer_mutex;
#endif


ngx_thread_volatile ngx_rbtree_t  ngx_event_timer_rbtree;
static ngx_rbtree_node_t          ngx_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    ngx_event_timer_rbtree.root = &ngx_event_timer_sentinel;
    ngx_event_timer_rbtree.sentinel = &ngx_event_timer_sentinel;
    ngx_event_timer_rbtree.insert = ngx_rbtree_insert_timer_value;

#if (NGX_THREADS)

    if (ngx_event_timer_mutex) {
        ngx_event_timer_mutex->log = log;
        return NGX_OK;
    }

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
    ngx_msec_int_t      timer;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    ngx_mutex_lock(ngx_event_timer_mutex);

    root = ngx_event_timer_rbtree.root;
    sentinel = ngx_event_timer_rbtree.sentinel;

    node = ngx_rbtree_min(root, sentinel);

    ngx_mutex_unlock(ngx_event_timer_mutex);

    timer = (ngx_msec_int_t) node->key - (ngx_msec_int_t) ngx_current_msec;

    return (ngx_msec_t) (timer > 0 ? timer : 0);
}


void
ngx_event_expire_timers(void)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = ngx_event_timer_rbtree.sentinel;

    for ( ;; ) {

        ngx_mutex_lock(ngx_event_timer_mutex);

        root = ngx_event_timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = ngx_rbtree_min(root, sentinel);

        /* node->key <= ngx_current_time */

        if ((ngx_msec_int_t) node->key - (ngx_msec_int_t) ngx_current_msec <= 0)
        {
            ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));

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
                           ngx_event_ident(ev->data), ev->timer.key);

            ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

            ngx_mutex_unlock(ngx_event_timer_mutex);

#if (NGX_DEBUG)
            ev->timer.left = NULL;
            ev->timer.right = NULL;
            ev->timer.parent = NULL;
#endif

            ev->timer_set = 0;

#if (NGX_THREADS)
            if (ngx_threaded) {
                ev->posted_timedout = 1;

                ngx_post_event(ev, &ngx_posted_events);

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
