
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_int_t ngx_poll_init(ngx_cycle_t *cycle);
static void ngx_poll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_poll_add_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_poll_del_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_poll_process_events(ngx_cycle_t *cycle);
static char *ngx_poll_init_conf(ngx_cycle_t *cycle, void *conf);


static struct pollfd  *event_list;
static int             nevents;

#if 0
static ngx_event_t   **ready_index;
#endif

static ngx_event_t    *accept_events;


static ngx_str_t    poll_name = ngx_string("poll");

ngx_event_module_t  ngx_poll_module_ctx = {
    &poll_name,
    NULL,                                  /* create configuration */
    ngx_poll_init_conf,                    /* init configuration */

    {
        ngx_poll_add_event,                /* add an event */
        ngx_poll_del_event,                /* delete an event */
        ngx_poll_add_event,                /* enable an event */
        ngx_poll_del_event,                /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* process the changes */
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
    NULL                                   /* init process */
};



static ngx_int_t ngx_poll_init(ngx_cycle_t *cycle)
{
    struct pollfd   *list;

    if (event_list == NULL) {
        nevents = 0;
    }

    if (ngx_process == NGX_PROCESS_WORKER
        || cycle->old_cycle == NULL
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

#if 0
        if (ready_index) {
            ngx_free(ready_index);
        }

        ngx_test_null(ready_index,
                      ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
                                cycle->log),
                      NGX_ERROR);
#endif
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_poll_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT|NGX_USE_ONESHOT_EVENT;

    return NGX_OK;
}


static void ngx_poll_done(ngx_cycle_t *cycle)
{
    ngx_free(event_list);
#if 0
    ngx_free(ready_index);
#endif

    event_list = NULL;
#if 0
    ready_index = NULL;
#endif
}


static ngx_int_t ngx_poll_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = ev->data;

    ev->active = 1;

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
                       "poll add index: %d", e->index);

        event_list[e->index].events |= event;
        ev->index = e->index;
    }

    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    return NGX_OK;
}


static ngx_int_t ngx_poll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_uint_t          i;
    ngx_cycle_t       **cycle;
    ngx_event_t        *e;
    ngx_connection_t   *c;

    c = ev->data;

    ev->active = 0;

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

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "index: copy event %d to %d", nevents, ev->index);

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
                }

                if (c->write->index == (u_int) nevents) {
                    c->write->index = ev->index;
                }
            }
        }

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll del index: %d", e->index);

        event_list[e->index].events &= ~event;
    }

    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static ngx_int_t ngx_poll_process_events(ngx_cycle_t *cycle)
{
    int                 ready;
    ngx_int_t           i, nready;
    ngx_uint_t          n, found, lock, expire;
    ngx_msec_t          timer;
    ngx_err_t           err;
    ngx_cycle_t       **old_cycle;
    ngx_event_t        *ev;
    ngx_epoch_msec_t    delta;
    ngx_connection_t   *c;
    struct timeval      tv;

    for ( ;; ) {
        timer = ngx_event_find_timer();

        if (timer != 0) {
            break;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "poll expired timer");

        ngx_event_expire_timers((ngx_msec_t)
                                (ngx_elapsed_msec - ngx_old_elapsed_msec));
    }

    /* NGX_TIMER_INFINITE == INFTIM */

    if (timer == NGX_TIMER_INFINITE) {
        expire = 0;

    } else {
        expire = 1;
    }

    ngx_old_elapsed_msec = ngx_elapsed_msec; 

#if (NGX_DEBUG0)
    if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %d: fd:%d ev:%04X",
                           i, event_list[i].fd, event_list[i].events);
        }
    }
#endif

    if (ngx_accept_mutex) {
        if (ngx_accept_disabled > 0) {
            ngx_accept_disabled--;

        } else {
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (ngx_accept_mutex_held == 0
                && (timer == NGX_TIMER_INFINITE
                    || timer > ngx_accept_mutex_delay))
            { 
                timer = ngx_accept_mutex_delay;
                expire = 0;
            } 
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "poll timer: %d", timer);

    ready = poll(event_list, (u_int) nevents, (int) timer);

    if (ready == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "poll ready %d of %d", ready, nevents);

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "poll() failed");
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }

    if (timer != NGX_TIMER_INFINITE) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "poll timer: %d, delta: %d", timer, (int) delta);
    } else {
        if (ready == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "poll() returned no events without timeout");
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        }
    }

    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }

    lock = 1;
    nready = 0;

    for (i = 0; i < nevents && ready; i++) {

#if 0
        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "poll: %d: fd:%d ev:%04X rev:%04X",
                       i, event_list[i].fd,
                       event_list[i].events, event_list[i].revents);
#else
        if (event_list[i].revents) {
            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %d: fd:%d ev:%04X rev:%04X",
                           i, event_list[i].fd,
                           event_list[i].events, event_list[i].revents);
        }
#endif

        if (event_list[i].revents & POLLNVAL) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "poll() error fd:%d ev:%04X rev:%04X",
                          event_list[i].fd,
                          event_list[i].events, event_list[i].revents);
        }

        if (event_list[i].revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL))
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange poll() events fd:%d ev:%04X rev:%04X",
                          event_list[i].fd,
                          event_list[i].events, event_list[i].revents);
        }

        if (event_list[i].fd == -1) {
            /*
             * the disabled event, a workaround for our possible bug,
             * see the comment below
             */
            continue;
        }

        c = &ngx_cycle->connections[event_list[i].fd];

        if (c->fd == -1) {
            old_cycle = ngx_old_cycles.elts;
            for (n = 0; n < ngx_old_cycles.nelts; n++) {
                if (old_cycle[n] == NULL) {
                    continue;
                }
                c = &old_cycle[n]->connections[event_list[i].fd];
                if (c->fd != -1) {
                    break;
                }
            }
        }

        if (c->fd == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "unexpected event");

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

            ev = c->read;
            ev->ready = 1;

            if (ev->oneshot) {
                if (ev->timer_set) {
                    ngx_del_timer(ev);
                }
                ngx_poll_del_event(ev, NGX_READ_EVENT, 0);
            }

            if (ev->accept) {
                ev->next = accept_events;
                accept_events = ev;
            } else {
                ngx_post_event(ev);
            }

#if 0
            ready_index[nready++] = c->read;
#endif
        }

        if (event_list[i].revents & (POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            found = 1;
            ev = c->write;
            ev->ready = 1;

            if (ev->oneshot) {
                if (ev->timer_set) {
                    ngx_del_timer(ev);
                }
                ngx_poll_del_event(ev, NGX_WRITE_EVENT, 0);
            }

            ngx_post_event(ev);
#if 0
            ready_index[nready++] = c->write;
#endif
        }

        if (found) {
            ready--;
            continue;
        }
    }

#if 0
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
#endif

    ev = accept_events;

    for ( ;; ) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "accept event " PTR_FMT, ev);

        if (ev == NULL) {
            break;
        }

        ngx_mutex_unlock(ngx_posted_events_mutex);

        ev->event_handler(ev);

        if (ngx_accept_disabled > 0) {
            lock = 0;
            break;
        }

        ev = ev->next;

        if (ev == NULL) {
            lock = 0;
            break;
        }

        if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        }

    }

    ngx_accept_mutex_unlock();
    accept_events = NULL;

    if (lock) {
        ngx_mutex_unlock(ngx_posted_events_mutex);
    }

    if (ready != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "poll ready != events");
    }

    if (expire && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    if (!ngx_threaded) {
        ngx_event_process_posted(cycle);
    }

    return nready;
}


static char *ngx_poll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ecf->use != ngx_poll_module.ctx_index) {
        return NGX_CONF_OK;
    }

#if (NGX_THREADS)

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "poll() is not supported in the threaded mode");
    return NGX_CONF_ERROR;

#else

    return NGX_CONF_OK;

#endif
}
