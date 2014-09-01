
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_int_t ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_select_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_select_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_select_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);
static void ngx_select_repair_fd_sets(ngx_cycle_t *cycle);
static char *ngx_select_init_conf(ngx_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;

static ngx_uint_t     max_read;
static ngx_uint_t     max_write;
static ngx_uint_t     nevents;

static ngx_event_t  **event_index;


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
    NGX_MODULE_V1,
    &ngx_select_module_ctx,                /* module context */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_event_t  **index;

    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    if (ngx_process >= NGX_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        index = ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
                          cycle->log);
        if (index == NULL) {
            return NGX_ERROR;
        }

        if (event_index) {
            ngx_memcpy(index, event_index, sizeof(ngx_event_t *) * nevents);
            ngx_free(event_index);
        }

        event_index = index;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_select_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT;

    max_read = 0;
    max_write = 0;

    return NGX_OK;
}


static void
ngx_select_done(ngx_cycle_t *cycle)
{
    ngx_free(event_index);

    event_index = NULL;
}


static ngx_int_t
ngx_select_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "select add event fd:%d ev:%i", c->fd, event);

    if (ev->index != NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "select event fd:%d ev:%i is already set", c->fd, event);
        return NGX_OK;
    }

    if ((event == NGX_READ_EVENT && ev->write)
        || (event == NGX_WRITE_EVENT && !ev->write))
    {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "invalid select %s event fd:%d ev:%i",
                      ev->write ? "write" : "read", c->fd, event);
        return NGX_ERROR;
    }

    if ((event == NGX_READ_EVENT && max_read >= FD_SETSIZE)
        || (event == NGX_WRITE_EVENT && max_write >= FD_SETSIZE))
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

    ev->active = 1;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NGX_OK;
}


static ngx_int_t
ngx_select_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == NGX_INVALID_INDEX) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%i", c->fd, event);

    if (event == NGX_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);
        max_read--;

    } else if (event == NGX_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
        max_write--;
    }

    if (ev->index < --nevents) {
        e = event_index[nevents];
        event_index[ev->index] = e;
        e->index = ev->index;
    }

    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static ngx_int_t
ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int                ready, nready;
    ngx_err_t          err;
    ngx_uint_t         i, found;
    ngx_event_t       *ev, **queue;
    struct timeval     tv, *tp;
    ngx_connection_t  *c;

#if (NGX_DEBUG)
    if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }
    }
#endif

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timer / 1000);
        tv.tv_usec = (long) ((timer % 1000) * 1000);
        tp = &tv;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select timer: %M", timer);

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;

    if (max_read || max_write) {
        ready = select(0, &work_read_fd_set, &work_write_fd_set, NULL, tp);

    } else {

        /*
         * Winsock select() requires that at least one descriptor set must be
         * be non-null, and any non-null descriptor set must contain at least
         * one handle to a socket.  Otherwise select() returns WSAEINVAL.
         */

        ngx_msleep(timer);

        ready = 0;
    }

    err = (ready == -1) ? ngx_socket_errno : 0;

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err, "select() failed");

        if (err == WSAENOTSOCK) {
            ngx_select_repair_fd_sets(cycle);
        }

        return NGX_ERROR;
    }

    if (ready == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "select() returned no events without timeout");
        return NGX_ERROR;
    }

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

            queue = ev->accept ? &ngx_posted_accept_events
                               : &ngx_posted_events;

            ngx_post_event(ev, queue);

            nready++;
        }
    }

    if (ready != nready) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "select ready != events: %d:%d", ready, nready);

        ngx_select_repair_fd_sets(cycle);
    }

    return NGX_OK;
}


static void
ngx_select_repair_fd_sets(ngx_cycle_t *cycle)
{
    int           n;
    u_int         i;
    socklen_t     len;
    ngx_err_t     err;
    ngx_socket_t  s;

    for (i = 0; i < master_read_fd_set.fd_count; i++) {

        s = master_read_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = ngx_socket_errno;

            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (i = 0; i < master_write_fd_set.fd_count; i++) {

        s = master_write_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = ngx_socket_errno;

            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }
}


static char *
ngx_select_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ecf->use != ngx_select_module.ctx_index) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}
