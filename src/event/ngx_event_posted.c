
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_thread_volatile ngx_event_t  *ngx_posted_events;
#if (NGX_THREADS)
ngx_mutex_t                      *ngx_posted_events_mutex;
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

void ngx_event_thread_handler(ngx_event_t *ev)
{
    if ((!ev->posted && !ev->active)
        || (ev->use_instance && ev->instance != ev->returned_instance))
    {
        /*
         * the stale event from a file descriptor
         * that was just closed in this iteration
         */

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "kevent: stale event " PTR_FMT, ev);
        return;
    }

    if (ev->posted) {
        ev->posted = 0;
    }

    ev->event_handler(ev);
}

#endif
