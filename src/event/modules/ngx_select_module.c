
/*
 * Copyright (C) 2002-2003 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_connection.h>
#include <ngx_event.h>


static int ngx_select_init(ngx_log_t *log);
static void ngx_select_done(ngx_log_t *log);
static int ngx_select_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_select_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_select_process_events(ngx_log_t *log);

static char *ngx_select_init_conf(ngx_pool_t *pool, void *conf);


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

static u_int          nevents;

static ngx_event_t  **event_index;
static ngx_event_t  **ready_index;


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
    NULL                                   /* init module */
};


static int ngx_select_init(ngx_log_t *log)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(ngx_event_module);

    FD_ZERO(&master_read_fd_set);
    FD_ZERO(&master_write_fd_set);

    ngx_test_null(event_index,
                  ngx_alloc(sizeof(ngx_event_t *) * 2 * ecf->connections, log),
                  NGX_ERROR);

    ngx_test_null(ready_index,
                  ngx_alloc(sizeof(ngx_event_t *) * 2 * ecf->connections, log),
                  NGX_ERROR);

    nevents = 0;

    if (ngx_event_timer_init(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_event_actions = ngx_select_module_ctx.actions;

    ngx_event_flags = NGX_HAVE_LEVEL_EVENT
                      |NGX_HAVE_ONESHOT_EVENT
                      |NGX_USE_LEVEL_EVENT;

#if (WIN32)
    max_read = max_write = 0;
#else
    max_fd = -1;
#endif

    return NGX_OK;
}


static void ngx_select_done(ngx_log_t *log)
{
    ngx_event_timer_done(log);

    ngx_free(event_index);
    ngx_free(ready_index);
}


static int ngx_select_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    c = ev->data;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "select fd:%d event:%d" _ c->fd _ event);
#endif

    if (ev->index != NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "%d:%d is already set", c->fd, event);
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
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NGX_OK;
}


static int ngx_select_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    if (ev->index == NGX_INVALID_INDEX) {
        return NGX_OK;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(c->log, "del event: %d, %d" _ c->fd _ event);
#endif

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

    if (ev->index < --nevents) {
        event_index[ev->index] = event_index[nevents];
        event_index[ev->index]->index = ev->index;
    }

    ev->active = 0;
    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static int ngx_select_process_events(ngx_log_t *log)
{
    int                ready, found;
    u_int              i, nready;
    ngx_msec_t         timer, delta;
    ngx_event_t       *ev;
    ngx_connection_t  *c;
    struct timeval     tv, *tp;

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;

    timer = ngx_event_find_timer();

    if (timer) {
        tv.tv_sec = timer / 1000;
        tv.tv_usec = (timer % 1000) * 1000;
        tp = &tv;
        delta = ngx_msec();

    } else {
        timer = 0;
        tp = NULL;
        delta = 0;
    }

#if !(WIN32)
    if (max_fd == -1) {
        for (i = 0; i < nevents; i++) {
            c = (ngx_connection_t *) event_index[i]->data;
            if (max_fd < c->fd) {
                max_fd = c->fd;
            }
        }

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "change max_fd: %d" _ max_fd);
#endif
    }
#endif

#if (NGX_DEBUG_EVENT)
    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = (ngx_connection_t *) ev->data;
        ngx_log_debug(log, "select: %d:%d" _ c->fd _ ev->write);
    }

    ngx_log_debug(log, "select timer: %d" _ timer);
#endif

#if (WIN32)
    if ((ready = select(0, &work_read_fd_set, &work_write_fd_set, NULL, tp))
#else
    if ((ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set,
                        NULL, tp))
#endif
               == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, "select() failed");
        return NGX_ERROR;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "select ready %d" _ ready);
#endif

    if (timer) {
        /* TODO: Linux returns time in tv */
        delta = ngx_msec() - delta;
        ngx_event_expire_timers(delta);

    } else {
        if (ready == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "select() returns no events without timeout");
            return NGX_ERROR;
        }
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "select timer: %d, delta: %d" _ timer _ delta);
#endif

    nready = 0;

    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = (ngx_connection_t *) ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                found = 1;
#if (NGX_DEBUG_EVENT)
                ngx_log_debug(log, "select write %d" _ c->fd);
#endif
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found = 1;
#if (NGX_DEBUG_EVENT)
                ngx_log_debug(log, "select read %d" _ c->fd);
#endif
            }
        }

        if (found) {
            ready_index[nready++] = ev;
        }
    }

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
                ev->timer_set = 0;
            }

            if (ev->write) {
                ngx_select_del_event(ev, NGX_WRITE_EVENT, 0);
            } else {
                ngx_select_del_event(ev, NGX_READ_EVENT, 0);
            }
        }

        ev->event_handler(ev);
    }

    if (ready != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "select ready != events");
    }

    return NGX_OK;
}


static char *ngx_select_init_conf(ngx_pool_t *pool, void *conf)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(ngx_event_module);

    if (ecf->connections > FD_SETSIZE) {
        return "maximum number of connections "
               "supported by select() is " ngx_value(FD_SETSIZE);
    }

    return NGX_CONF_OK;
}
