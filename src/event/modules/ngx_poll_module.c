
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_time.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_poll_module.h>


/* should be per-thread */
static struct pollfd  *event_list;
static int             nevents;

static ngx_event_t   **event_index;
static ngx_event_t     timer_queue;
/* */

int ngx_poll_init(int max_connections, ngx_log_t *log)
{
    ngx_test_null(event_list,
                  ngx_alloc(sizeof(struct pollfd) * max_connections, log),
                  NGX_ERROR);

    ngx_test_null(event_index,
                  ngx_alloc(sizeof(ngx_event_t *) * max_connections, log),
                  NGX_ERROR);

    nevents = 0;

    timer_queue.timer_prev = &timer_queue;
    timer_queue.timer_next = &timer_queue;

    ngx_event_actions.add = ngx_poll_add_event;
    ngx_event_actions.del = ngx_poll_del_event;
    ngx_event_actions.timer = ngx_poll_add_timer;
    ngx_event_actions.process = ngx_poll_process_events;

    return NGX_OK;
}

int ngx_poll_add_event(ngx_event_t *ev, int event, u_int flags)
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

    return NGX_OK;
}

int ngx_poll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t      *e;
    ngx_connection_t *c;

    c = (ngx_connection_t *) ev->data;

    if (ev->index == NGX_INVALID_INDEX)
        return NGX_OK;

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

    ngx_log_debug(c->log, "del event: %d, %d" _ c->fd _ event);

    if (e == NULL || e->index == NGX_INVALID_INDEX) {
        if (ev->index < --nevents) {
            event_list[ev->index] = event_list[nevents];
            event_index[ev->index] = event_index[nevents];
            event_index[ev->index]->index = ev->index;
        }

    } else {
        event_list[e->index].events &= ~event;
    }

    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}

int ngx_poll_process_events(ngx_log_t *log)
{
    int                i, ready, found;
    u_int              timer, delta;
    ngx_err_t          err;
    ngx_event_t       *ev;
    ngx_connection_t  *c;

    if (timer_queue.timer_next != &timer_queue) {
        timer = timer_queue.timer_next->timer_delta;
        delta = ngx_msec();

    } else {
        timer = INFTIM;
        delta = 0;
    }

#if 1
    /* DEBUG */
    for (i = 0; i < nevents; i++) {
        ngx_log_debug(log, "poll: %d, %d" _
                      event_list[i].fd _ event_list[i].events);
    }
#endif

    ngx_log_debug(log, "poll timer: %d" _ timer);

    if ((ready = poll(event_list, nevents, timer)) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "poll() failed");
        return NGX_ERROR;
    }

    ngx_log_debug(log, "poll ready %d" _ ready);

    if (timer != INFTIM) {
        delta = ngx_msec() - delta;

    } else {
        ngx_assert((ready != 0), return NGX_ERROR, log,
                   "poll() returns no events without timeout");
    }

    ngx_log_debug(log, "poll timer: %d, delta: %d" _ timer _ delta);

    if (timer != INFTIM) {
        if (delta >= timer) {
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

    for (i = 0; i < nevents && ready; i++) {
        c = &ngx_connections[event_list[i].fd];

        ngx_log_debug(log, "poll: fd:%d, ev:%d, rev:%d" _
                      event_list[i].fd _
                      event_list[i].events _ event_list[i].revents);

        found = 0;

        if (event_list[i].revents & POLLIN) {
            found = 1;
            c->read->ready = 1;

            if (c->read->oneshot) {
                ngx_del_timer(c->read);
                ngx_poll_del_event(c->read, NGX_READ_EVENT, 0);
            }

            if (c->read->event_handler(c->read) == NGX_ERROR) {
                c->read->close_handler(c->read);
            }
        }

        if (event_list[i].revents & POLLOUT) {
            found = 1;
            c->write->ready = 1;

            if (c->write->oneshot) {
                ngx_del_timer(c->write);
                ngx_poll_del_event(c->write, NGX_WRITE_EVENT, 0);
            }

            if (c->write->event_handler(c->write) == NGX_ERROR) {
                c->write->close_handler(c->write);
            }
        }

        if (event_list[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            found = 1;

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

    ngx_assert((ready == 0), /* void */ ; , log, "poll ready != nevents");

    return NGX_OK;
}

void ngx_poll_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t *e;

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
