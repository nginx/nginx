/*
 * Copyright (C) 2002-2003 Igor Sysoev, http://sysoev.ru
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
#if 1
int              kq;
#else
static int              kq;
#endif
static struct kevent   *change_list, *event_list;
static unsigned int     nchanges;
static int              nevents;

static ngx_event_t     *timer_queue;
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

    timer_queue = ngx_event_init_timer(log);
    if (timer_queue == NULL) {
        return NGX_ERROR;
    }

#if !(USE_KQUEUE)
    ngx_event_actions.add = ngx_kqueue_add_event;
    ngx_event_actions.del = ngx_kqueue_del_event;
    ngx_event_actions.timer = ngx_event_add_timer;
    ngx_event_actions.process = ngx_kqueue_process_events;

#if (HAVE_AIO_EVENT)

    ngx_event_flags = NGX_HAVE_AIO_EVENT;

#else

    ngx_event_flags = NGX_HAVE_LEVEL_EVENT
                     |NGX_HAVE_ONESHOT_EVENT

#if (HAVE_CLEAR_EVENT)
                     |NGX_HAVE_CLEAR_EVENT
#else
                     |NGX_USE_LEVEL_EVENT
#endif

#if (HAVE_LOWAT_EVENT)
                     |NGX_HAVE_LOWAT_EVENT
#endif

                     |NGX_HAVE_KQUEUE_EVENT;

    ngx_write_chain_proc = ngx_freebsd_write_chain;

#endif

#endif

    return NGX_OK;
}


void ngx_kqueue_done(ngx_log_t *log)
{
    if (close(kq) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "kqueue close() failed");
    }
}


int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    /* The event addition or change should be always passed to a kernel
       because there can be case when event was passed to a kernel then
       added again to the change_list and then deleted from the change_list
       by ngx_kqueue_del_event() so the first event still remains in a kernel */

#if 0

    if (nchanges > 0
        && ev->index < nchanges
        && change_list[ev->index].udata == ev)
    {
#if (NGX_DEBUG_EVENT)
        ngx_connection_t *c = (ngx_connection_t *) ev->data;
        ngx_log_debug(ev->log, "kqueue add event: %d: ft:%d" _ c->fd _ event);
#endif

        /* if the event is still not passed to a kernel we change it */

        change_list[ev->index].filter = event;
        change_list[ev->index].flags = flags;

        return NGX_OK;
    }

#endif

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

        /* if the event is still not passed to a kernel we will not pass it */

        if (ev->index < --nchanges) {
            e = (ngx_event_t *) change_list[nchanges].udata;
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NGX_OK;
    }

    /* when a socket is closed kqueue automatically deletes its filters 
       so we do not need to delete a event explicity before a socket closing */

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
    change_list[nchanges].udata = ev;

#if (HAVE_LOWAT_EVENT)

    if ((flags & EV_ADD) && ev->lowat > 0) {
        change_list[nchanges].fflags = NOTE_LOWAT;
        change_list[nchanges].data = ev->lowat;

    } else {
        change_list[nchanges].fflags = 0;
        change_list[nchanges].data = 0;
    }

#else

    change_list[nchanges].fflags = 0;
    change_list[nchanges].data = 0;

#endif

    ev->index = nchanges;

    nchanges++;

    return NGX_OK;
}


int ngx_kqueue_process_events(ngx_log_t *log)
{
    int              events, i;
    ngx_msec_t       timer, delta;
    ngx_event_t      *ev;
    struct timeval   tv;
    struct timespec  ts, *tp;

    timer = ngx_event_find_timer();

    if (timer) {
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

        /* Expired timers must be deleted before the events processing
           because the new timers can be added during the processing */

        ngx_event_expire_timers(delta);

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
        if (event_list[i].ident > 0x8000000) {
            ngx_log_debug(log,
                          "kevent: %08x: ft:%d f:%08x ff:%08x d:%d ud:%08x" _
                          event_list[i].ident _ event_list[i].filter _
                          event_list[i].flags _ event_list[i].fflags _
                          event_list[i].data _ event_list[i].udata);
        } else {
            ngx_log_debug(log,
                          "kevent: %d: ft:%d f:%08x ff:%08x d:%d ud:%08x" _
                          event_list[i].ident _ event_list[i].filter _
                          event_list[i].flags _ event_list[i].fflags _
                          event_list[i].data _ event_list[i].udata);
        }
#endif

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, event_list[i].data,
                          "kevent error on %d", event_list[i].ident);
            continue;
        }

        ev = (ngx_event_t *) event_list[i].udata;

        /* It's a stale event from a socket
           that was just closed in this iteration */

        if (!ev->active) {
           continue;
        }

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            if (ev->first) {
                if (nchanges > 0
                    && ev->index < nchanges
                    && change_list[ev->index].udata == ev) {

                    /* It's a stale event from a socket that was just closed
                       in this iteration and during processing another socket
                       was opened with the same number by accept() or socket()
                       and its event has been added the event to the change_list
                       but has not been passed to a kernel.  Nevertheless
                       there's small chance that ngx_kqueue_set_event() has
                       flushed the new event if the change_list was filled up.
                       In this very rare case we would get EAGAIN while
                       a reading or a writing */

                    continue;

                } else {
                    ev->first = 0;
                }
            }
 
            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->eof = 1;
                ev->error = event_list[i].fflags;
            }

            if (ev->oneshot) {
                ngx_del_timer(ev);
            }

            /* fall through */

        case EVFILT_AIO:
            ev->ready = 1;

            if (ev->event_handler(ev) == NGX_ERROR) {
                ev->close_handler(ev);
            }

            break;


        default:
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "unknown kevent filter %d" _ event_list[i].filter);
        }
    }

    return NGX_OK;
}
