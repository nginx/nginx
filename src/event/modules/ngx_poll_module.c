
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_time.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>
#include <ngx_poll_module.h>


/* should be per-thread */
static struct pollfd  *event_list;
static u_int           nevents;

static ngx_event_t   **event_index;
static ngx_event_t   **ready_index;
static ngx_event_t    *timer_queue;
/* */

int ngx_poll_init(int max_connections, ngx_log_t *log)
{
    ngx_test_null(event_list,
                  ngx_alloc(sizeof(struct pollfd) * max_connections, log),
                  NGX_ERROR);

    ngx_test_null(event_index,
                  ngx_alloc(sizeof(ngx_event_t *) * max_connections, log),
                  NGX_ERROR);

    ngx_test_null(ready_index,
                  ngx_alloc(sizeof(ngx_event_t *) * 2 * max_connections, log),
                  NGX_ERROR);

    nevents = 0;

    timer_queue = ngx_event_init_timer(log);
    if (timer_queue == NULL) {
        return NGX_ERROR;
    }

    ngx_event_actions.add = ngx_poll_add_event;
    ngx_event_actions.del = ngx_poll_del_event;
    ngx_event_actions.timer = ngx_event_add_timer;
    ngx_event_actions.process = ngx_poll_process_events;

    return NGX_OK;
}

int ngx_poll_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    ev->active = 1;
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

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "add event: %d:%d" _ c->fd _ event);
#endif

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

    return NGX_OK;
}

int ngx_poll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    if (ev->index == NGX_INVALID_INDEX) {
        return NGX_OK;
    }

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

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(c->log, "del event: %d, %d" _ c->fd _ event);
#endif

    if (e == NULL || e->index == NGX_INVALID_INDEX) {
        if (ev->index < --nevents) {
            event_list[ev->index] = event_list[nevents];
            event_index[ev->index] = event_index[nevents];
            event_index[ev->index]->index = ev->index;
        }

    } else {
        event_list[e->index].events &= ~event;
    }

    ev->active = 0;
    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}

int ngx_poll_process_events(ngx_log_t *log)
{
    int                ready, found;
    u_int              i, nready;
    ngx_msec_t         timer, delta;
    ngx_err_t          err;
    ngx_event_t       *ev;
    ngx_connection_t  *c;

    timer = ngx_event_find_timer();

    if (timer) {
        delta = ngx_msec();

    } else {
        timer = INFTIM;
        delta = 0;
    }

#if (NGX_DEBUG_EVENT)
    for (i = 0; i < nevents; i++) {
        ngx_log_debug(log, "poll: %d, %d" _
                      event_list[i].fd _ event_list[i].events);
    }

    ngx_log_debug(log, "poll timer: %d" _ timer);
#endif

    if ((ready = poll(event_list, nevents, timer)) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "poll() failed");
        return NGX_ERROR;
    }

    ngx_log_debug(log, "poll ready %d" _ ready);

    if ((int) timer != INFTIM) {
        delta = ngx_msec() - delta;
        ngx_event_expire_timers(delta);

    } else {
        if (ready == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "poll() returns no events without timeout");
            return NGX_ERROR;
        }
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "poll timer: %d, delta: %d" _ timer _ delta);
#endif

    nready = 0;

    for (i = 0; i < nevents && ready; i++) {
        c = &ngx_connections[event_list[i].fd];

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "poll: fd:%d, ev:%d, rev:%d" _
                      event_list[i].fd _
                      event_list[i].events _ event_list[i].revents);
#endif

        found = 0;

        if (event_list[i].revents & POLLIN) {
            found = 1;
            ready_index[nready++] = c->read;
        }

        if (event_list[i].revents & POLLOUT) {
            found = 1;
            ready_index[nready++] = c->write;
        }

        if (event_list[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            found = 1;

            /* need ot add to ready_index[nready++] = c->read or c->write; */

            err = 0;
            if (event_list[i].revents & POLLNVAL) {
                err = EBADF;
            }

            ngx_log_error(NGX_LOG_ERR, log, err,
                          "poll() error on %d:%d",
                          event_list[i].fd, event_list[i].revents);
        }

        if (found) {
            ready--;
        }
    }

    for (i = 0; i < nready; i++) {
        ev = ready_index[i];

        if (!ev->active) {
            continue;
        }

        ev->ready = 1;

        if (ev->oneshot) {
            ngx_del_timer(ev);

            if (ev->write) {
                ngx_poll_del_event(ev, NGX_WRITE_EVENT, 0);
            } else {
                ngx_poll_del_event(ev, NGX_READ_EVENT, 0);
            }
        }

        if (ev->event_handler(ev) == NGX_ERROR) {
            ev->close_handler(ev);
        }
    }

    if (ready != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "poll ready != events");
    }

    return NGX_OK;
}
