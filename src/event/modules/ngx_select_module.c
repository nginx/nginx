
/*
 * Copyright (C) Igor Sysoev
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
static char *ngx_select_init_conf(ngx_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;

#if (NGX_WIN32)
static ngx_uint_t     max_read;
static ngx_uint_t     max_write;
#else
static ngx_int_t      max_fd;
#endif

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

    if (ngx_process == NGX_PROCESS_WORKER
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

#if (NGX_WIN32)
    max_read = max_write = 0;
#else
    max_fd = -1;
#endif

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

#if (NGX_WIN32)

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

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NGX_OK;
}


static ngx_int_t
ngx_select_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == NGX_INVALID_INDEX) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%i", c->fd, event);

#if (NGX_WIN32)

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

    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static ngx_int_t
ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int                 ready, nready;
    ngx_uint_t          i, found;
    ngx_err_t           err;
    ngx_event_t        *ev, **queue;
    ngx_connection_t   *c;
    struct timeval      tv, *tp;
#if !(NGX_WIN32)
    ngx_uint_t          level;
#endif

#if !(NGX_WIN32)

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

#if !(NGX_WIN32)
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "max_fd: %d", max_fd);
#endif
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

#if 1
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   /*
                    * (void *) disables "dereferencing type-punned
                    * pointer will break strict-aliasing rules
                    */
                   "select read fd_set: %08Xd",
                   *(int *) (void *) &work_read_fd_set);
#endif

#if (NGX_WIN32)

    ready = select(0, &work_read_fd_set, &work_write_fd_set, NULL, tp);

#else

    ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set, NULL, tp);

#endif

    if (ready == -1) {
        err = ngx_socket_errno;
    } else {
        err = 0;
    }

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update(0, 0);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

#if (NGX_WIN32)

    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err, "select() failed");
        return NGX_ERROR;
    }

#else

    if (err) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "select() failed");
        return NGX_ERROR;
    }

#endif

    if (ready == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "select() returned no events without timeout");
        return NGX_ERROR;
    }

    ngx_mutex_lock(ngx_posted_events_mutex);

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

            queue = (ngx_event_t **) (ev->accept ? &ngx_posted_accept_events:
                                                   &ngx_posted_events);
            ngx_locked_post_event(ev, queue);

            nready++;
        }
    }

    ngx_mutex_unlock(ngx_posted_events_mutex);

    if (ready != nready) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "select ready != events");
    }

    return NGX_OK;
}


static char *
ngx_select_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ecf->use != ngx_select_module.ctx_index) {
        return NGX_CONF_OK;
    }

    /* disable warning: the default FD_SETSIZE is 1024U in FreeBSD 5.x */

#if !(NGX_WIN32)

    if ((unsigned) ecf->connections > FD_SETSIZE) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "the maximum number of files "
                      "supported by select() is " ngx_value(FD_SETSIZE));
        return NGX_CONF_ERROR;
    }

#endif

#if (NGX_THREADS) && !(NGX_WIN32)

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "select() is not supported in the threaded mode");
    return NGX_CONF_ERROR;

#else

    return NGX_CONF_OK;

#endif
}
