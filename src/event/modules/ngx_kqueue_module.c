/*
 * Copyright (C) 2002 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>
#include <ngx_kqueue_module.h>

#if (USE_KQUEUE) && !(HAVE_KQUEUE)
#error "kqueue is not supported on this platform"
#endif


/* STUB */
#define KQUEUE_NCHANGES  512
#define KQUEUE_NEVENTS   512


/* should be per-thread */
static int              kq;
static struct kevent   *change_list, *event_list;
static unsigned int     nchanges;
static int              nevents;

static ngx_event_t      timer_queue;
/* */


int ngx_kqueue_init(int max_connections, ngx_log_t *log)
{
    int  change_size, event_size;

    nevents = KQUEUE_NEVENTS;
    nchanges = 0;
    change_size = sizeof(struct kevent) * KQUEUE_NCHANGES;
    event_size = sizeof(struct kevent) * KQUEUE_NEVENTS;

    kq = kqueue();

    if (kq == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "kqueue() failed");
        return NGX_ERROR;
    }

    ngx_test_null(change_list, ngx_alloc(change_size, log), NGX_ERROR);
    ngx_test_null(event_list, ngx_alloc(event_size, log), NGX_ERROR);

    if (ngx_event_init_timer(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

#if 0
    timer_queue.timer_prev = &timer_queue;
    timer_queue.timer_next = &timer_queue;
#endif

#if !(USE_KQUEUE)
    ngx_event_actions.add = ngx_kqueue_add_event;
    ngx_event_actions.del = ngx_kqueue_del_event;
    ngx_event_actions.timer = ngx_kqueue_add_timer;
    ngx_event_actions.process = ngx_kqueue_process_events;
#endif

    return NGX_OK;
}


int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    if (nchanges > 0
        && ev->index < nchanges
        && change_list[ev->index].udata == ev)
    {
#if (NGX_DEBUG_EVENT)
        ngx_connection_t *c = (ngx_connection_t *) ev->data;
        ngx_log_debug(ev->log, "kqueue add event: %d: ft:%d" _ c->fd _ event);
#endif
        change_list[ev->index].filter = event;
        change_list[ev->index].flags = flags;

        return NGX_OK;
    }

    return ngx_kqueue_set_event(ev, event, EV_ADD | flags);
}


int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t  *e;

    ev->active = 0;

    if (nchanges > 0
        && ev->index < nchanges
        && change_list[ev->index].udata == ev)
    {
#if (NGX_DEBUG_EVENT)
        ngx_connection_t *c = (ngx_connection_t *) ev->data;
        ngx_log_debug(ev->log, "kqueue del event: %d: ft:%d" _ c->fd _ event);
#endif
        if (ev->index < --nchanges) {
            e = (ngx_event_t *) change_list[nchanges].udata;
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NGX_OK;
    }

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    return ngx_kqueue_set_event(ev, event, EV_DELETE);
}


int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags)
{
    struct timespec    ts;
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "kqueue set event: %d: ft:%d f:%08x" _
                  c->fd _ filter _ flags);
#endif

    if (nchanges >= KQUEUE_NCHANGES) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(kq, change_list, nchanges, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].ident = c->fd;
    change_list[nchanges].filter = filter;
    change_list[nchanges].flags = flags;
    change_list[nchanges].fflags = 0;
    change_list[nchanges].data = 0;
    change_list[nchanges].udata = ev;

    ev->index = nchanges;

    nchanges++;

    return NGX_OK;
}


int ngx_kqueue_process_events(ngx_log_t *log)
{
    int              events, i;
    u_int            timer, delta;
    ngx_event_t      *ev;
    struct timeval   tv;
    struct timespec  ts, *tp;

    if (timer_queue.timer_next != &timer_queue) {
        timer = timer_queue.timer_next->timer_delta;
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    } else {
        timer = 0;
        delta = 0;
        tp = NULL;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "kevent timer: %d" _ timer);
#endif

    events = kevent(kq, change_list, nchanges, event_list, nevents, tp);

    if (events == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "kevent failed");
        return NGX_ERROR;
    }

    nchanges = 0;

    if (timer) {
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;

    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "kevent returns no events without timeout");
            return NGX_ERROR;
        }
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "kevent timer: %d, delta: %d" _ timer _ delta);
#endif

    for (i = 0; i < events; i++) {

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "kevent: %d: ft:%d f:%08x ff:%08x d:%d ud:%08x" _
                      event_list[i].ident _ event_list[i].filter _
                      event_list[i].flags _ event_list[i].fflags _
                      event_list[i].data _ event_list[i].udata);
#endif

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, event_list[i].data,
                          "kevent error on %d", event_list[i].ident);
            continue;
        }

        ev = (ngx_event_t *) event_list[i].udata;

        if (!ev->active) {
           continue;
        }

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:
            ev->ready = 1;
            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->eof = 1;
                ev->error = event_list[i].fflags;
            }

            if (ev->oneshot) {
                ngx_del_timer(ev);
            }

            if (ev->event_handler(ev) == NGX_ERROR) {
                ev->close_handler(ev);
            }

            break;

        default:
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "unknown kevent filter %d" _ event_list[i].filter);
        }
    }

    if (timer && timer_queue.timer_next != &timer_queue) {
        if (delta >= timer_queue.timer_next->timer_delta) {
            for ( ;; ) {
                ev = timer_queue.timer_next;

                if (ev == &timer_queue || delta < ev->timer_delta) {
                    break;
                }

                delta -= ev->timer_delta;

                ngx_del_timer(ev);
                ev->timedout = 1;
                if (ev->event_handler(ev) == NGX_ERROR) {
                    ev->close_handler(ev);
                }
            }

        } else {
           timer_queue.timer_next->timer_delta -= delta;
        }
    }

    return NGX_OK;
}


void ngx_kqueue_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t  *e;

#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
    ngx_log_debug(ev->log, "set timer: %d:%d" _ c->fd _ timer);
#endif

    if (ev->timer_next || ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already set");
        return;
    }

    for (e = timer_queue.timer_next;
         e != &timer_queue && timer > e->timer_delta;
         e = e->timer_next)
    {
        timer -= e->timer_delta;
    }

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}
