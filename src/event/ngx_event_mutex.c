
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_int_t ngx_event_mutex_timedlock(ngx_event_mutex_t *m, ngx_msec_t timer,
                                    ngx_event_t *ev)
{
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "lock event mutex %p lock:%XD", m, m->lock);

    if (m->lock) {

        if (m->events == NULL) {
            m->events = ev;

        } else {
            m->last->next = ev;
        }

        m->last = ev;
        ev->next = NULL;

#if (NGX_THREADS0)
        ev->light = 1;
#endif

        ngx_add_timer(ev, timer);

        return NGX_AGAIN;
    }

    m->lock = 1;

    return NGX_OK;
}


ngx_int_t ngx_event_mutex_unlock(ngx_event_mutex_t *m, ngx_log_t *log)
{
    ngx_event_t  *ev;

    if (m->lock == 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "tring to unlock the free event mutex %p", m);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                   "unlock event mutex %p, next event: %p", m, m->events);

    m->lock = 0;

    if (m->events) {
        ev = m->events;
        m->events = ev->next;

        ev->next = (ngx_event_t *) ngx_posted_events;
        ngx_posted_events = ev;
    }

    return NGX_OK;
}
