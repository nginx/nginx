/*
 * Copyright (C) 2002 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_devpoll_module.h>

#if (USE_DEVPOLL) && !(HAVE_DEVPOLL)
#error "/dev/poll is not supported on this platform"
#endif


/* should be per-thread */
static int              dp;
static struct pollfd   *change_list, *event_list;
static int              nchanges, nevents;

static ngx_event_t      timer_queue;
/* */


int ngx_devpoll_init(int max_connections, ngx_log_t *log)
{
    int size;

    size = sizeof(struct pollfd) * 512;
    nchanges = 0;
    nevents = 512;

    dp = open("/dev/poll", O_RDWR);

    if (dp == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "open(/dev/poll) failed");
        return NGX_ERROR;
    }

    ngx_test_null(change_list, ngx_alloc(size, log), NGX_ERROR);
    ngx_test_null(event_list, ngx_alloc(size, log), NGX_ERROR);
    ngx_test_null(event_index, ngx_alloc(sizeof(ngx_event_t *) * nevents, log),
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


/* NOT READY */

int ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t      *e;
    ngx_connection_t *c;

    c = (ngx_connection_t *) ev->data;

    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    if (event == NGX_READ_EVENT) {
        e = c->write;
#if (NGX_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (NGX_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    ngx_log_debug(ev->log, "poll fd:%d event:%d" _ c->fd _ event);

    if (e == NULL || e->index == NGX_INVALID_INDEX) {
        event_list[nevents].fd = c->fd;
        event_list[nevents].events = event;
        event_list[nevents].revents = 0;

        event_index[nevents] = ev;
        ev->index = nevents;
        nevents++;

    } else {
        event_list[e->index].events |= event;
        ev->index = e->index;
    }

    return ngx_devpoll_set_event(ev, event, EV_ADD | flags);
}

/* NOT READY */

int ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t *e;

    if (nchanges > 0 && ev->index < nchanges
        && change_list[ev->index].udata == ev)
    {
        ngx_connection_t *cn = (ngx_connection_t *) ev->data;
        ngx_log_debug(ev->log, "kqueue del event: %d: ft:%d" _
                      cn->fd _ event);

        if (ev->index < --nchanges) {
            e = (ngx_event_t *) change_list[nchanges].udata;
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NGX_OK;
    }

    if (flags & NGX_CLOSE_EVENT)
        return NGX_OK;

    return ngx_devpoll_set_event(ev, POLLREMOVE);
}

/* NOT READY */

int ngx_devpoll_set_event(ngx_event_t *ev, int event)
{
    int  n;
    ngx_connection_t *c;

    c = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "devpoll fd:%d event:%d" _ c->fd _ event);

    if (nchanges >= nevents) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "/dev/pool change list is filled up");

        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != n) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "write(/dev/poll) failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    event_list[nchanges].fd = c->fd;
    event_list[nchanges].events = event;
    event_list[nchanges].revents = 0;

    event_index[nchanges] = ev;
    ev->index = nchanges;

/*
    if (flags == EV_ADD)
        ev->index = nchanges;
*/

    nchanges++;

    return NGX_OK;
}


int ngx_devpoll_process_events(ngx_log_t *log)
{
    int              events, i;
    u_int            timer, delta;
    ngx_event_t      *ev;
    struct dvpoll    dvpoll;
    struct timeval   tv;

    if (timer_queue.timer_next != &timer_queue) {
        timer = timer_queue.timer_next->timer_delta;
#if 1
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
        delta = ngx_msec();
#endif

    } else {
        timer = INFTIM;
        delta = 0;
    }

    ngx_log_debug(log, "devpoll timer: %d" _ timer);

    n = nchanges * sizeof(struct pollfd);
    if (write(dp, change_list, n) != n) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "write(/dev/poll) failed");
        return NGX_ERROR;
    }

    dvpoll.dp_fds = event_list;
    dvpoll.dp_nfds = nevents;
    dvpoll.dp_timeout = timer;
    events = ioctl(dp, DP_POLL, &dvpoll);

    if (events == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "ioctl(DP_POLL) failed");
        return NGX_ERROR;
    }

    nchanges = 0;

    if (timer != INFTIM) {
#if 1
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;
#else
        delta = ngx_msec() - delta;
#endif

    } else {
        ngx_assert((events != 0), return NGX_ERROR, log,
                   "ioctl(DP_POLL) returns no events without timeout");
    }

    ngx_log_debug(log, "devpoll timer: %d, delta: %d" _ timer _ delta);

    if (timer != INFTIM) {
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

        ngx_log_debug(log, "devpoll: %d: ev:%d rev:%d" _
                      event_list[i].fd _
                      event_list[i].events _ event_list[i].revents);


        if (event_list[i].revents & POLLIN) {
            c->read->ready = 1;
            
            if (c->read->oneshot) {
                ngx_del_timer(c->read);
                ngx_select_del_event(c->read, NGX_READ_EVENT, 0);
            }

            if (c->read->event_handler(c->read) == NGX_ERROR) {
                c->read->close_handler(c->read);
            }   
        }

        if (event_list[i].revents & POLLOUT) {
            c->write->ready = 1;

            if (c->write->oneshot) {
                ngx_del_timer(c->write);
                ngx_select_del_event(c->write, NGX_WRITE_EVENT, 0);
            }

            if (c->write->event_handler(c->write) == NGX_ERROR) {
                c->write->close_handler(c->write);
            }   
        }

        if (event_list[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "ioctl(DP_POLL) error on %d:%d",
                          event_list[i].fd, event_list[i].revents);
        }
    }

    return NGX_OK;
}


void ngx_devpoll_add_timer(ngx_event_t *ev, ngx_msec_t timer)
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
