
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>



static ngx_int_t ngx_select_init(ngx_cycle_t *cycle);
static void ngx_select_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_select_add_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_select_del_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_select_process_events(ngx_cycle_t *cycle);
static char *ngx_select_init_conf(ngx_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;

#if (WIN32)
static int            max_read;
static int            max_write;
#else
static int            max_fd;
#endif

static ngx_uint_t     nevents;

static ngx_event_t  **event_index;
#if 0
static ngx_event_t  **ready_index;
#endif

static ngx_event_t   *accept_events;


static ngx_str_t    select_name = ngx_string("select");

ngx_event_module_t  ngx_select_module_ctx = {
    &select_name,
    NULL,                                  /* create configuration */
    ngx_select_init_conf,                  /* init configuration */

    {
        ngx_select_add_event,              /* add an event */
        ngx_select_del_event,              /* delete an event */
        ngx_select_add_event,              /* enable an event */
        ngx_select_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* process the changes */
        ngx_select_process_events,         /* process the events */
        ngx_select_init,                   /* init the events */
        ngx_select_done                    /* done the events */
    }

};

ngx_module_t  ngx_select_module = {
    NGX_MODULE,
    &ngx_select_module_ctx,                /* module context */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static ngx_int_t ngx_select_init(ngx_cycle_t *cycle)
{
    ngx_event_t  **index;

    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    if (ngx_process == NGX_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        ngx_test_null(index,
                      ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
                                cycle->log),
                      NGX_ERROR);

        if (event_index) {
            ngx_memcpy(index, event_index, sizeof(ngx_event_t *) * nevents);
            ngx_free(event_index);
        }
        event_index = index;

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

    ngx_event_actions = ngx_select_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT|NGX_USE_ONESHOT_EVENT;

#if (WIN32)
    max_read = max_write = 0;
#else
    max_fd = -1;
#endif

    return NGX_OK;
}


static void ngx_select_done(ngx_cycle_t *cycle)
{
    ngx_free(event_index);
#if 0
    ngx_free(ready_index);
#endif

    event_index = NULL;
}


static ngx_int_t ngx_select_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "select add event fd:%d ev:%d", c->fd, event);

    if (ev->index != NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "select event fd:%d ev:%d is already set", c->fd, event);
        return NGX_OK;
    }

#if (WIN32)

    if ((event == NGX_READ_EVENT) && (max_read >= FD_SETSIZE)
        || (event == NGX_WRITE_EVENT) && (max_write >= FD_SETSIZE))
    {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                      "maximum number of descriptors "
                      "supported by select() is %d", FD_SETSIZE);
        return NGX_ERROR;
    }

    if (event == NGX_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);
        max_read++;

    } else if (event == NGX_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
        max_write++;
    }

#else

    if (event == NGX_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);

    } else if (event == NGX_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
    }

    if (max_fd != -1 && max_fd < c->fd) {
        max_fd = c->fd;
    }

#endif

    ev->active = 1;
    ev->oneshot = (u_char) ((flags & NGX_ONESHOT_EVENT) ? 1 : 0);

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NGX_OK;
}


static ngx_int_t ngx_select_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == NGX_INVALID_INDEX) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%d", c->fd, event);

#if (WIN32)

    if (event == NGX_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);
        max_read--;

    } else if (event == NGX_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
        max_write--;
    }

#else

    if (event == NGX_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);

    } else if (event == NGX_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
    }

    if (max_fd == c->fd) {
        max_fd = -1;
    }

#endif

    if (ev->index < (u_int) --nevents) {
        event_index[ev->index] = event_index[nevents];
        event_index[ev->index]->index = ev->index;
    }

    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static ngx_int_t ngx_select_process_events(ngx_cycle_t *cycle)
{
    int                       ready, nready;
    ngx_uint_t                i, found, lock, expire;
    ngx_err_t                 err;
    ngx_msec_t                timer;
    ngx_event_t              *ev;
    ngx_connection_t         *c;
    ngx_epoch_msec_t          delta;
    struct timeval            tv, *tp;
#if (HAVE_SELECT_CHANGE_TIMEOUT)
    static ngx_epoch_msec_t   deltas = 0;
#endif

    for ( ;; ) {
        timer = ngx_event_find_timer();

        if (timer != 0) {
            break;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "select expired timer");

        ngx_event_expire_timers((ngx_msec_t)
                                    (ngx_elapsed_msec - ngx_old_elapsed_msec));
    }

    ngx_old_elapsed_msec = ngx_elapsed_msec;

    expire = 1;

#if !(WIN32)

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

    if (max_fd == -1) {
        for (i = 0; i < nevents; i++) {
            c = event_index[i]->data;
            if (max_fd < c->fd) {
                max_fd = c->fd;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "change max_fd: %d", max_fd);
    }

#endif

#if (NGX_DEBUG)
    if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }

#if !(WIN32)
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "max_fd: %d", max_fd);
#endif
    }
#endif

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;
        expire = 0;

    } else {
        tv.tv_sec = timer / 1000;
        tv.tv_usec = (timer % 1000) * 1000;
        tp = &tv;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select timer: %d", timer);

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select read fd_set: %08X", *(int *) &work_read_fd_set);

#if (WIN32)
    ready = select(0, &work_read_fd_set, &work_write_fd_set, NULL, tp);
#else
    ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set, NULL, tp);
#endif

    if (ready == -1) {
        err = ngx_socket_errno;
    } else {
        err = 0;
    }

#if (HAVE_SELECT_CHANGE_TIMEOUT)

    if (timer != NGX_TIMER_INFINITE) {
        delta = timer - (tv.tv_sec * 1000 + tv.tv_usec / 1000);

        /*
         * learn the real time and update the cached time
         * if the sum of the last deltas overcomes 1 second
         */

        deltas += delta;
        if (deltas > 1000) {
            ngx_gettimeofday(&tv);
            ngx_time_update(tv.tv_sec);
            deltas = tv.tv_usec / 1000;

            ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;
        } else {
            ngx_elapsed_msec += delta;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "select timer: %d, delta: %d", timer, (int) delta);

    } else {
        delta = 0;
        ngx_gettimeofday(&tv);
        ngx_time_update(tv.tv_sec);

        ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;

        if (ready == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "select() returned no events without timeout");
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        }
    }

#else /* !(HAVE_SELECT_CHANGE_TIMEOUT) */

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;

    if (timer != NGX_TIMER_INFINITE) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "select timer: %d, delta: %d", timer, (int) delta);

    } else {
        if (ready == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "select() returned no events without timeout");
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        }
    }

#endif /* HAVE_SELECT_CHANGE_TIMEOUT */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
#if (WIN32)
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err, "select() failed");
#else
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "select() failed");
#endif
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }


    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }

    lock = 1;
    nready = 0;

    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                found = 1;
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select write %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found = 1;
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select read %d", c->fd);
            }
        }

        if (found) {
            ev->ready = 1;

            if (ev->oneshot) {
                if (ev->timer_set) {
                    ngx_del_timer(ev);
                }

                if (ev->write) {
                    ngx_select_del_event(ev, NGX_WRITE_EVENT, 0);
                } else {
                    ngx_select_del_event(ev, NGX_READ_EVENT, 0);
                }
            }

            if (ev->accept) {
                ev->next = accept_events;
                accept_events = ev;
            } else {
                ngx_post_event(ev);
            }

            nready++;

#if 0
            ready_index[nready++] = ev;
#endif
        }
    }

#if 0
    for (i = 0; i < nready; i++) {
        ev = ready_index[i];
        ready--;

        if (!ev->active) {
            continue;
        }

        ev->ready = 1;

        if (ev->oneshot) {
            if (ev->timer_set) {
                ngx_del_timer(ev);
            }

            if (ev->write) {
                ngx_select_del_event(ev, NGX_WRITE_EVENT, 0);
            } else {
                ngx_select_del_event(ev, NGX_READ_EVENT, 0);
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

    if (ready != nready) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "select ready != events");
    }

    if (expire && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    if (!ngx_threaded) {
        ngx_event_process_posted(cycle);
    }

    return NGX_OK;
}


static char *ngx_select_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ecf->use != ngx_select_module.ctx_index) {
        return NGX_CONF_OK;
    }

    /* disable warning: the default FD_SETSIZE is 1024U in FreeBSD 5.x */

#if !(WIN32)
    if ((unsigned) ecf->connections > FD_SETSIZE) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "the maximum number of files "
                      "supported by select() is " ngx_value(FD_SETSIZE));
        return NGX_CONF_ERROR;
    }
#endif

#if (NGX_THREADS)
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "select() is not supported in the threaded mode");
    return NGX_CONF_ERROR;
#else
    return NGX_CONF_OK;
#endif
}
