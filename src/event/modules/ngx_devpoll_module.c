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
#include <ngx_devpoll_module.h>

#if (USE_DEVPOLL) && !(HAVE_DEVPOLL)
#error "/dev/poll is not supported on this platform"
#endif


/* STUB */
#define DEVPOLL_NCHANGES  512
#define DEVPOLL_NEVENTS   512

/* should be per-thread */
static int              dp;
static struct pollfd   *change_list, *event_list;
static unsigned int     nchanges;
static int              nevents;

static ngx_event_t    **change_index;

static ngx_event_t      timer_queue;
/* */


int ngx_devpoll_init(int max_connections, ngx_log_t *log)
{
    int  change_size, event_size;

    nevents = DEVPOLL_NEVENTS;
    nchanges = 0;
    change_size = sizeof(struct pollfd) * DEVPOLL_NCHANGES;
    event_size = sizeof(struct pollfd) * DEVPOLL_NEVENTS;

    dp = open("/dev/poll", O_RDWR);

    if (dp == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "open(/dev/poll) failed");
        return NGX_ERROR;
    }

    ngx_test_null(change_list, ngx_alloc(change_size, log), NGX_ERROR);
    ngx_test_null(event_list, ngx_alloc(event_size, log), NGX_ERROR);
    ngx_test_null(change_index,
                  ngx_alloc(sizeof(ngx_event_t *) * DEVPOLL_NCHANGES, log),
                  NGX_ERROR);

    timer_queue.timer_prev = &timer_queue;
    timer_queue.timer_next = &timer_queue;

#if !(USE_DEVPOLL)
    ngx_event_actions.add = ngx_devpoll_add_event;
    ngx_event_actions.del = ngx_devpoll_del_event;
    ngx_event_actions.timer = ngx_devpoll_add_timer;
    ngx_event_actions.process = ngx_devpoll_process_events;
#endif

    return NGX_OK;
}


int ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags)
{
#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
#endif

#if (NGX_READ_EVENT != POLLIN)
    if (event == NGX_READ_EVENT) {
        event = POLLOUT;
#if (NGX_WRITE_EVENT != POLLOUT)
    } else {
        event = POLLIN;
#endif
    }
#endif

#if (NGX_DEBUG_EVENT)
    c = (ngx_connection_t *) ev->data;
    ngx_log_debug(ev->log, "add event: %d:%d" _ c->fd _ event);
#endif

    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    return ngx_devpoll_set_event(ev, event, 0);
}


int ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t  *e;

#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
    ngx_log_debug(c->log, "del event: %d, %d" _ c->fd _ event);
#endif

    if (ngx_devpoll_set_event(ev, POLLREMOVE, flags) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ev->active = 0;

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    if (event == NGX_READ_EVENT) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e) {
        return ngx_devpoll_set_event(e, event, 0);
    }

    return NGX_OK;
}


int ngx_devpoll_set_event(ngx_event_t *ev, int event, u_int flags)
{
    int  n;
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "devpoll fd:%d event:%d flush:%d" _
                           c->fd _ event _ flags);
#endif

    if (nchanges >= DEVPOLL_NCHANGES) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "/dev/pool change list is filled up");

        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != n) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "write(/dev/poll) failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].fd = c->fd;
    change_list[nchanges].events = event;
    change_list[nchanges].revents = 0;

    change_index[nchanges] = ev;
    ev->index = nchanges;

    nchanges++;

    if (flags & NGX_CLOSE_EVENT) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != n) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "write(/dev/poll) failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    return NGX_OK;
}


int ngx_devpoll_process_events(ngx_log_t *log)
{
    int                events, n, i;
    u_int              timer, delta;
    ngx_err_t          err;
    ngx_event_t       *ev;
    ngx_connection_t  *c;
    struct dvpoll      dvp;
    struct timeval     tv;

    if (timer_queue.timer_next != &timer_queue) {
        timer = timer_queue.timer_next->timer_delta;
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    } else {
        timer = INFTIM;
        delta = 0;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "devpoll timer: %d" _ timer);
#endif

    if (nchanges) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != n) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "write(/dev/poll) failed");
            return NGX_ERROR;
        }
    }

    dvp.dp_fds = event_list;
    dvp.dp_nfds = nevents;
    dvp.dp_timeout = timer;
    events = ioctl(dp, DP_POLL, &dvp);

    if (events == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "ioctl(DP_POLL) failed");
        return NGX_ERROR;
    }

    nchanges = 0;

    if (timer != INFTIM) {
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;

    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "ioctl(DP_POLL) returns no events without timeout");
            return NGX_ERROR;
        }
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "devpoll timer: %d, delta: %d" _ timer _ delta);
#endif

    for (i = 0; i < events; i++) {

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "devpoll: %d: ev:%d rev:%d" _
                      event_list[i].fd _
                      event_list[i].events _ event_list[i].revents);
#endif

        c = &ngx_connections[event_list[i].fd];

        if (event_list[i].revents & POLLIN) {
            if (!c->read->active) {
                continue;
            }

            c->read->ready = 1;

            if (c->read->oneshot) {
                ngx_del_timer(c->read);
                ngx_devpoll_del_event(c->read, NGX_READ_EVENT, 0);
            }

            if (c->read->event_handler(c->read) == NGX_ERROR) {
                c->read->close_handler(c->read);
            }   
        }

        if (event_list[i].revents & POLLOUT) {
            if (!c->write->active) {
                continue;
            }

            c->write->ready = 1;

            if (c->write->oneshot) {
                ngx_del_timer(c->write);
                ngx_devpoll_del_event(c->write, NGX_WRITE_EVENT, 0);
            }

            if (c->write->event_handler(c->write) == NGX_ERROR) {
                c->write->close_handler(c->write);
            }   
        }

        if (event_list[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            err = 0;
            if (event_list[i].revents & POLLNVAL) {
                err = EBADF;
            }

            ngx_log_error(NGX_LOG_ERR, log, err,
                          "ioctl(DP_POLL) error on %d:%d",
                          event_list[i].fd, event_list[i].revents);
        }
    }

    if (timer != INFTIM && timer_queue.timer_next != &timer_queue) {
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


void ngx_devpoll_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t *e;

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
