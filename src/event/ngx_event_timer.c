
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_THREADS)
ngx_mutex_t  *ngx_event_timer_mutex;
#endif


ngx_thread_volatile ngx_rbtree_t  *ngx_event_timer_rbtree;
ngx_rbtree_t                       ngx_event_timer_sentinel;


ngx_int_t ngx_event_timer_init(ngx_log_t *log)
{
    if (ngx_event_timer_rbtree) {
#if (NGX_THREADS)
        ngx_event_timer_mutex->log = log;
#endif
        return NGX_OK;
    }

    ngx_event_timer_rbtree = &ngx_event_timer_sentinel;

#if (NGX_THREADS)
    if (!(ngx_event_timer_mutex = ngx_mutex_init(log, 0))) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


ngx_msec_t ngx_event_find_timer(void)
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

    timer = (ngx_msec_t)
         (node->key * NGX_TIMER_RESOLUTION -
               ngx_elapsed_msec / NGX_TIMER_RESOLUTION * NGX_TIMER_RESOLUTION);
#if 0
                         (node->key * NGX_TIMER_RESOLUTION - ngx_elapsed_msec);
#endif

    return timer > 0 ? timer: 0 ;
}


void ngx_event_expire_timers(ngx_msec_t timer)
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

        if (node->key <= (ngx_msec_t)
                         (ngx_old_elapsed_msec + timer) / NGX_TIMER_RESOLUTION)
        {
            ev = (ngx_event_t *)
                           ((char *) node - offsetof(ngx_event_t, rbtree_key));

#if (NGX_THREADS)
            if (ngx_trylock(ev->lock) == 0) {
                break;
            }
#endif

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "event timer del: %d: %d",
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

            if (ngx_threaded) {
                if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                    return;
                }

                ev->posted_timedout = 1;
                ngx_post_event(ev);

                ngx_mutex_unlock(ngx_posted_events_mutex);
                continue;
            }

            ev->timedout = 1;

            ev->event_handler(ev);

            continue;
        }

        break;
    }

    ngx_mutex_unlock(ngx_event_timer_mutex);
}
