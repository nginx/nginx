
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_thread_volatile ngx_event_t  *ngx_posted_accept_events;
ngx_thread_volatile ngx_event_t  *ngx_posted_events;

#if (NGX_THREADS)
ngx_mutex_t                      *ngx_posted_events_mutex;
#endif


void
ngx_event_process_posted(ngx_cycle_t *cycle,
    ngx_thread_volatile ngx_event_t **posted)
{
    ngx_event_t  *ev;

    for ( ;; ) {

        ev = (ngx_event_t *) *posted;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        if (ev == NULL) {
            return;
        }

        ngx_delete_posted_event(ev);

        ev->handler(ev);
    }
}


#if (NGX_THREADS) && !(NGX_WIN32)

void
ngx_wakeup_worker_thread(ngx_cycle_t *cycle)
{
    ngx_int_t     i;
#if 0
    ngx_uint_t    busy;
    ngx_event_t  *ev;

    busy = 1;

    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        return;
    }

    for (ev = (ngx_event_t *) ngx_posted_events; ev; ev = ev->next) {
        if (*(ev->lock) == 0) {
            busy = 0;
            break;
        }
    }

    ngx_mutex_unlock(ngx_posted_events_mutex);

    if (busy) {
        return;
    }
#endif

    for (i = 0; i < ngx_threads_n; i++) {
        if (ngx_threads[i].state == NGX_THREAD_FREE) {
            ngx_cond_signal(ngx_threads[i].cv);
            return;
        }
    }
}


ngx_int_t
ngx_event_thread_process_posted(ngx_cycle_t *cycle)
{
    ngx_event_t  *ev;

    for ( ;; ) {

        ev = (ngx_event_t *) ngx_posted_events;

        for ( ;; ) {

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                          "posted event %p", ev);

            if (ev == NULL) {
                return NGX_OK;
            }

            if (ngx_trylock(ev->lock) == 0) {

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "posted event %p is busy", ev);

                ev = ev->next;
                continue;
            }

            if (ev->lock != ev->own_lock) {
                if (*(ev->own_lock)) {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                             "the own lock of the posted event %p is busy", ev);
                    ngx_unlock(ev->lock);
                    ev = ev->next;
                    continue;
                }
                *(ev->own_lock) = 1;
            }

            ngx_delete_posted_event(ev);

            ev->locked = 1;

            ev->ready |= ev->posted_ready;
            ev->timedout |= ev->posted_timedout;
            ev->pending_eof |= ev->posted_eof;
#if (NGX_HAVE_KQUEUE)
            ev->kq_errno |= ev->posted_errno;
#endif
            if (ev->posted_available) {
                ev->available = ev->posted_available;
            }

            ev->posted_ready = 0;
            ev->posted_timedout = 0;
            ev->posted_eof = 0;
#if (NGX_HAVE_KQUEUE)
            ev->posted_errno = 0;
#endif
            ev->posted_available = 0;

            ngx_mutex_unlock(ngx_posted_events_mutex);

            ev->handler(ev);

            ngx_mutex_lock(ngx_posted_events_mutex);

            if (ev->locked) {
                ngx_unlock(ev->lock);

                if (ev->lock != ev->own_lock) {
                    ngx_unlock(ev->own_lock);
                }
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "posted event %p is done", ev);

            break;
        }
    }
}

#else

void
ngx_wakeup_worker_thread(ngx_cycle_t *cycle)
{
}

#endif
