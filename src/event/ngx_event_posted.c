
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_thread_volatile ngx_event_t  *ngx_posted_events;

#if (NGX_THREADS)
ngx_mutex_t                      *ngx_posted_events_mutex;
ngx_cond_t                       *ngx_posted_events_cv;
#endif


void ngx_event_process_posted(ngx_cycle_t *cycle)
{
    ngx_event_t  *ev;

    for ( ;; ) {

        ev = (ngx_event_t *) ngx_posted_events;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event " PTR_FMT, ev);

        if (ev == NULL) {
            return;
        }

        ngx_posted_events = ev->next;

        if (ev->accept) {
            continue;
        }

        if ((!ev->posted && !ev->active)
            || (ev->use_instance && ev->instance != ev->returned_instance))
        {
            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "stale posted event " PTR_FMT, ev);
            continue;
        }

        if (ev->posted) {
            ev->posted = 0;
        }

        ev->event_handler(ev);
    }
}


#if (NGX_THREADS)

ngx_int_t ngx_event_thread_process_posted(ngx_cycle_t *cycle)
{
    ngx_event_t  *ev, **ep;

    for ( ;; ) {

        ev = (ngx_event_t *) ngx_posted_events;
        ep = (ngx_event_t **) &ngx_posted_events;

        for ( ;; ) {

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                          "posted event " PTR_FMT, ev);

            if (ev == NULL) {
                ngx_mutex_unlock(ngx_posted_events_mutex);
                return NGX_OK;
            }

            if (ngx_trylock(ev->lock) == 0) {

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "posted event " PTR_FMT " is busy", ev);

                ep = &ev->next;
                ev = ev->next;
                continue;
            }

            *ep = ev->next;

            if ((!ev->posted && !ev->active)
                || (ev->use_instance && ev->instance != ev->returned_instance))
            {
                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "kevent: stale event " PTR_FMT, ev);

                ev = ev->next;

                continue;
            }

            ngx_mutex_unlock(ngx_posted_events_mutex);

            if (ev->posted) {
                ev->posted = 0;
            }

            ev->event_handler(ev);

            ngx_unlock(ev->lock);

            if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;
        }
    }
}

#endif
