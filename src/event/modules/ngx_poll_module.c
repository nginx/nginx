
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static int ngx_poll_init(ngx_cycle_t *cycle);
static void ngx_poll_done(ngx_cycle_t *cycle);
static int ngx_poll_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_poll_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_poll_process_events(ngx_log_t *log);


static struct pollfd  *event_list;
static int             nevents;

static ngx_event_t   **ready_index;


static ngx_str_t    poll_name = ngx_string("poll");

ngx_event_module_t  ngx_poll_module_ctx = {
    &poll_name,
    NULL,                                  /* create configuration */
    NULL,                                  /* init configuration */

    {
        ngx_poll_add_event,                /* add an event */
        ngx_poll_del_event,                /* delete an event */
        ngx_poll_add_event,                /* enable an event */
        ngx_poll_del_event,                /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        ngx_poll_process_events,           /* process the events */
        ngx_poll_init,                     /* init the events */
        ngx_poll_done                      /* done the events */
    }

};

ngx_module_t  ngx_poll_module = {
    NGX_MODULE,
    &ngx_poll_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};



static int ngx_poll_init(ngx_cycle_t *cycle)
{
    struct pollfd   *list;

    if (event_list == NULL) {
        nevents = 0;
    }

    if (cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        ngx_test_null(list,
                      ngx_alloc(sizeof(struct pollfd) * cycle->connection_n,
                                cycle->log),
                      NGX_ERROR);

        if (event_list) {
            ngx_memcpy(list, event_list, sizeof(ngx_event_t *) * nevents);
            ngx_free(event_list);
        }

        event_list = list;

        if (ready_index) {
            ngx_free(ready_index);
        }

        ngx_test_null(ready_index,
                      ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
                                cycle->log),
                      NGX_ERROR);
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_poll_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT|NGX_USE_ONESHOT_EVENT;

    return NGX_OK;
}


static void ngx_poll_done(ngx_cycle_t *cycle)
{
    ngx_free(event_list);
    ngx_free(ready_index);

    event_list = NULL;
    ready_index = NULL;
}


static int ngx_poll_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = ev->data;

    if (ev->index != NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%d is already set", c->fd, event);
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

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll add event: fd:%d ev:%d", c->fd, event);

    if (e == NULL || e->index == NGX_INVALID_INDEX) {
        event_list[nevents].fd = c->fd;
        event_list[nevents].events = event;
        event_list[nevents].revents = 0;

        ev->index = nevents;
        nevents++;

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll index: %d", e->index);

        event_list[e->index].events |= event;
        ev->index = e->index;
    }

    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    return NGX_OK;
}


static int ngx_poll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_int_t           i;
    ngx_cycle_t       **cycle;
    ngx_event_t        *e;
    ngx_connection_t   *c;

    c = ev->data;

    if (ev->index == NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%d is already deleted",
                      c->fd, event);
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

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll del event: fd:%d ev:%d", c->fd, event);

    if (e == NULL || e->index == NGX_INVALID_INDEX) {
        nevents--;

        if (ev->index < (u_int) nevents) {
            event_list[ev->index] = event_list[nevents];

            c = &ngx_cycle->connections[event_list[nevents].fd];

            if (c->fd == -1) {
                cycle = ngx_old_cycles.elts;
                for (i = 0; i < ngx_old_cycles.nelts; i++) {
                    if (cycle[i] == NULL) {
                        continue;
                    }
                    c = &cycle[i]->connections[event_list[nevents].fd];
                    if (c->fd != -1) {
                        break;
                    }
                }
            }

            if (c->fd == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                              "unexpected last event");

            } else {
                if (c->read->index == (u_int) nevents) {
                    c->read->index = ev->index;

                } else if (c->write->index == (u_int) nevents) {
                    c->write->index = ev->index;

                } else {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                                  "unexpected last event index");
                }
            }
        }

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll index: %d", e->index);

        event_list[e->index].events &= ~event;
    }

    ev->active = 0;
    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static int ngx_poll_process_events(ngx_log_t *log)
{
    int                 ready;
    ngx_int_t           i, j, nready, found;
    ngx_msec_t          timer;
    ngx_err_t           err;
    ngx_cycle_t       **cycle;
    ngx_event_t        *ev;
    ngx_epoch_msec_t    delta;
    ngx_connection_t   *c;
    struct timeval      tv;

    timer = ngx_event_find_timer();
    ngx_old_elapsed_msec = ngx_elapsed_msec; 

    if (timer == 0) {
        timer = (ngx_msec_t) INFTIM;
    }

#if (NGX_DEBUG0)
    for (i = 0; i < nevents; i++) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0, "poll: %d: fd:%d ev:%04X",
                       i, event_list[i].fd, event_list[i].events);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "poll timer: %d", timer);
#endif

    ready = poll(event_list, (u_int) nevents, (int) timer);

    if (ready == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ngx_start_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "poll ready %d", ready);

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      log, err, "poll() failed");
        return NGX_ERROR;
    }

    if (timer != (ngx_msec_t) INFTIM) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "poll timer: %d, delta: %d", timer, (int) delta);
    } else {
        if (ready == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "poll() returned no events without timeout");
            return NGX_ERROR;
        }
    }

    nready = 0;

    for (i = 0; i < nevents && ready; i++) {

#if 0
        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                       "poll: %d: fd:%d ev:%04X rev:%04X",
                       i, event_list[i].fd,
                       event_list[i].events, event_list[i].revents);
#else
        if (event_list[i].revents) {
            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                           "poll: %d: fd:%d ev:%04X rev:%04X",
                           i, event_list[i].fd,
                           event_list[i].events, event_list[i].revents);
        }
#endif

        if (event_list[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "poll() error fd:%d ev:%04X rev:%04X",
                          event_list[i].fd,
                          event_list[i].events, event_list[i].revents);
        }

        if (event_list[i].revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL))
        {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "strange poll() events fd:%d ev:%04X rev:%04X",
                          event_list[i].fd,
                          event_list[i].events, event_list[i].revents);
        }

        if (event_list[i].fd == -1) {

            /* the disabled event, workaround for our possible bug */

            continue;
        }

        c = &ngx_cycle->connections[event_list[i].fd];

        if (c->fd == -1) {
            cycle = ngx_old_cycles.elts;
            for (j = 0; j < ngx_old_cycles.nelts; j++) {
                if (cycle[j] == NULL) {
                    continue;
                }
                c = &cycle[j]->connections[event_list[i].fd];
                if (c->fd != -1) {
                    break;
                }
            }
        }

        if (c->fd == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "unexpected event");

            /*
             * it is certainly our fault and it should be investigated,
             * in the meantime we disable this event to avoid a CPU spinning
             */

            if (i == nevents - 1) {
                nevents--;
            } else {
                event_list[i].fd = -1;
            }

            continue;
        }

        found = 0;

        if (event_list[i].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
            found = 1;
            ready_index[nready++] = c->read;
        }

        if (event_list[i].revents & (POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            found = 1;
            ready_index[nready++] = c->write;
        }

        if (found) {
            ready--;
            continue;
        }
    }

    for (i = 0; i < nready; i++) {
        ev = ready_index[i];

        if (!ev->active) {
            continue;
        }

        ev->ready = 1;

        if (ev->oneshot) {
            if (ev->timer_set) {
                ngx_del_timer(ev);
            }

            if (ev->write) {
                ngx_poll_del_event(ev, NGX_WRITE_EVENT, 0);
            } else {
                ngx_poll_del_event(ev, NGX_READ_EVENT, 0);
            }
        }

        ev->event_handler(ev);
    }

    if (ready != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "poll ready != events");
    }

    if (timer != (ngx_msec_t) INFTIM && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    return NGX_OK;
}
