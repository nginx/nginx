/*
 * Copyright (C) 2002 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_kqueue_module.h>

#if (USE_KQUEUE) && !(HAVE_KQUEUE)
#error "kqueue is not supported on this platform"
#endif



static int              kq;
static struct kevent   *change_list, *event_list;
static int              nchanges, nevents;

static ngx_event_t      timer_queue;

int ngx_kqueue_init(int max_connections, ngx_log_t *log)
{
    int size = sizeof(struct kevent) * 512;

    nchanges = 0;
    nevents = 512;

    kq = kqueue();

    if (kq == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "kqueue() failed");
        return NGX_ERROR;
    }

    ngx_test_null(change_list, ngx_alloc(size, log), NGX_ERROR);
    ngx_test_null(event_list, ngx_alloc(size, log), NGX_ERROR);

    timer_queue.timer_prev = &timer_queue;
    timer_queue.timer_next = &timer_queue;

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
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    return ngx_kqueue_set_event(ev, event, EV_ADD | flags);
}

int ngx_kqueue_del_event(ngx_event_t *ev, int event)
{
    ngx_event_t *e;

    if (ev->index <= nchanges && change_list[ev->index].udata == ev) {
        change_list[ev->index] = change_list[nchanges];
        e = (ngx_event_t *) change_list[ev->index].udata;
        e->index = ev->index;
        nchanges--;

        return NGX_OK;
    }

    return ngx_kqueue_set_event(ev, event, EV_DELETE);
}

int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags)
{
    struct timespec  ts = { 0, 0 };
    ngx_connection_t *cn = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "kqueue set event: %d: ft:%d f:%08x" _
                  cn->fd _ filter _ flags);

    if (nchanges >= nevents) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        if (kevent(kq, change_list, nchanges, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent failed");
            return NGX_ERROR;
        }
        nchanges = 0;
    }

    change_list[nchanges].ident = cn->fd;
    change_list[nchanges].filter = filter;
    change_list[nchanges].flags = flags;
    change_list[nchanges].fflags = 0;
    change_list[nchanges].data = 0;
    change_list[nchanges].udata = ev;

    if (flags == EV_ADD)
        ev->index = nchanges;

    nchanges++;

    return NGX_OK;
}

int ngx_kqueue_process_events(ngx_log_t *log)
{
    int              events, i;
    u_int            timer = 0, delta = 0;
    ngx_event_t      *ev;
    struct timeval   tv;
    struct timespec  ts, *tp = NULL;

    if (timer_queue.timer_next != &timer_queue) {
        timer = timer_queue.timer_next->timer_delta;
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }

    ngx_log_debug(log, "kevent timer: %d" _ timer);

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
        ngx_assert((events != 0), return NGX_ERROR, log,
                   "kevent returns no events without timeout");
    }

    ngx_log_debug(log, "kevent timer: %d, delta: %d" _ timer _ delta);

    if (timer) {
        if (delta >= timer) {
            for ( ;; ) {
                ev = timer_queue.timer_next;

                if (ev == &timer_queue || delta < ev->timer_delta)
                    break;

                delta -= ev->timer_delta;
                ngx_del_timer(ev);
                ev->timedout = 1;
                if (ev->event_handler(ev) == NGX_ERROR)
                    ev->close_handler(ev);
            }

        } else {
           timer_queue.timer_next->timer_delta -= delta;
        }
    }

    for (i = 0; i < events; i++) {

        ngx_log_debug(log, "kevent: %d: ft:%d f:%08x ff:%08x d:%d ud:%08x" _
                      event_list[i].ident _ event_list[i].filter _
                      event_list[i].flags _ event_list[i].fflags _
                      event_list[i].data _ event_list[i].udata);

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, event_list[i].data,
                          "kevent error on %d", event_list[i].ident);
            continue;
        }

        ev = (ngx_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:
            ev->ready = 1;
            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->eof = 1;
                ev->error = event_list[i].fflags;
            }

            if (ev->oneshot)
                ngx_del_timer(ev);

            if (ev->event_handler(ev) == NGX_ERROR)
                ev->close_handler(ev);

            break;

        default:
            ngx_assert(0, /* void */, log,
                       "unknown kevent filter %d" _ event_list[i].filter);
        }
    }

    return NGX_OK;
}

void ngx_kqueue_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t *e;

    ngx_log_debug(ev->log, "set timer: %d" _ timer);

    ngx_assert((!ev->timer_next && !ev->timer_prev), return, ev->log,
               "timer already set");

    for (e = timer_queue.timer_next;
         e != &timer_queue && timer > e->timer_delta;
         e = e->timer_next)
        timer -= e->timer_delta;

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}
