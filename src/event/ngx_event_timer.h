
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_TIMER_H_INCLUDED_
#define _NGX_EVENT_TIMER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_TIMER_INFINITE  (ngx_msec_t) -1
#define NGX_TIMER_ERROR     (ngx_msec_t) -2


/*
 * the 32-bit timer key value resolution
 *
 * 1 msec - 24 days
 * 10 msec - 8 months
 * 50 msec - 3 years 5 months
 * 100 msec - 6 years 10 months
 */

#define NGX_TIMER_RESOLUTION  1

#define NGX_TIMER_LAZY_DELAY  300


ngx_int_t ngx_event_timer_init(ngx_log_t *log);
ngx_msec_t ngx_event_find_timer(void);
void ngx_event_expire_timers(ngx_msec_t timer);


#if (NGX_THREADS)
extern ngx_mutex_t  *ngx_event_timer_mutex;
#endif


extern ngx_thread_volatile ngx_rbtree_t  *ngx_event_timer_rbtree;
extern ngx_rbtree_t                       ngx_event_timer_sentinel;


static ngx_inline void
ngx_event_del_timer(ngx_event_t *ev)
{
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "event timer del: %d: %d",
                    ngx_event_ident(ev->data), ev->rbtree_key);

    if (ngx_mutex_lock(ngx_event_timer_mutex) == NGX_ERROR) {
        return;
    }

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
}


static ngx_inline void
ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_int_t  key;

    key = (ngx_int_t)
              (ngx_elapsed_msec / NGX_TIMER_RESOLUTION * NGX_TIMER_RESOLUTION
                                              + timer) / NGX_TIMER_RESOLUTION;
#if 0
                             (ngx_elapsed_msec + timer) / NGX_TIMER_RESOLUTION;
#endif

    if (ev->timer_set) {

        /*
         * Use the previous timer value if a difference between them is less
         * then NGX_TIMER_LAZY_DELAY milliseconds.  It allows to minimize
         * the rbtree operations for the fast connections.
         */

        if (abs(key - ev->rbtree_key)
                                 < NGX_TIMER_LAZY_DELAY / NGX_TIMER_RESOLUTION)
        {
            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "event timer: %d, old: %i, new: %i",
                            ngx_event_ident(ev->data), ev->rbtree_key, key);
            return;
        }

        ngx_del_timer(ev);
    }

    ev->rbtree_key = key;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "event timer add: %d: %i",
                    ngx_event_ident(ev->data), ev->rbtree_key);

    if (ngx_mutex_lock(ngx_event_timer_mutex) == NGX_ERROR) {
        return;
    }

    ngx_rbtree_insert((ngx_rbtree_t **) &ngx_event_timer_rbtree,
                      &ngx_event_timer_sentinel,
                      (ngx_rbtree_t *) &ev->rbtree_key);

    ngx_mutex_unlock(ngx_event_timer_mutex);

    ev->timer_set = 1;
}


#endif /* _NGX_EVENT_TIMER_H_INCLUDED_ */
