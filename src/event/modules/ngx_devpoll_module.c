
/*
 * Copyright (C) 2002-2003 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_connection.h>
#include <ngx_event.h>


#if (TEST_BUILD_DEVPOLL)

/* Solaris declarations */

#define POLLREMOVE   0x0800
#define DP_POLL      0xD001

struct dvpoll {
    struct pollfd  *dp_fds;
    int             dp_nfds;
    int             dp_timeout;
};

#endif


typedef struct {
    int   changes;
    int   events;
} ngx_devpoll_conf_t;


static int ngx_devpoll_init(ngx_log_t *log);
static void ngx_devpoll_done(ngx_log_t *log);
static int ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_devpoll_set_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_devpoll_process_events(ngx_log_t *log);

static void *ngx_devpoll_create_conf(ngx_pool_t *pool);
static char *ngx_devpoll_init_conf(ngx_pool_t *pool, void *conf);

/* STUB */
#define DEVPOLL_NCHANGES  512
#define DEVPOLL_NEVENTS   512

static int              dp;
static struct pollfd   *change_list, *event_list;
static u_int            nchanges, max_changes;
static int              nevents;

static ngx_event_t    **change_index;


static ngx_str_t      devpoll_name = ngx_string("/dev/poll");

static ngx_command_t  ngx_devpoll_commands[] = {

    {ngx_string("devpoll_changes"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_devpoll_conf_t, changes),
     NULL},

    {ngx_string("devpoll_events"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_devpoll_conf_t, events),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_devpoll_module_ctx = {
    &devpoll_name,
    ngx_devpoll_create_conf,               /* create configuration */
    ngx_devpoll_init_conf,                 /* init configuration */

    {
        ngx_devpoll_add_event,             /* add an event */
        ngx_devpoll_del_event,             /* delete an event */
        ngx_devpoll_add_event,             /* enable an event */
        ngx_devpoll_del_event,             /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        ngx_devpoll_process_events,        /* process the events */
        ngx_devpoll_init,                  /* init the events */
        ngx_devpoll_done,                  /* done the events */
    }

};

ngx_module_t  ngx_devpoll_module = {
    NGX_MODULE,
    &ngx_devpoll_module_ctx,               /* module context */
    ngx_devpoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL                                   /* init module */
};


static int ngx_devpoll_init(ngx_log_t *log)
{
    ngx_devpoll_conf_t  *dpcf;

    dpcf = ngx_event_get_conf(ngx_devpoll_module);

ngx_log_debug(log, "CH: %d" _ dpcf->changes);
ngx_log_debug(log, "EV: %d" _ dpcf->events);

    max_changes = dpcf->changes;
    nevents = dpcf->events;
    nchanges = 0;

    dp = open("/dev/poll", O_RDWR);

    if (dp == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "open(/dev/poll) failed");
        return NGX_ERROR;
    }

    ngx_test_null(change_list,
                  ngx_alloc(sizeof(struct pollfd) * dpcf->changes, log),
                  NGX_ERROR);

    ngx_test_null(event_list,
                  ngx_alloc(sizeof(struct pollfd) * dpcf->events, log),
                  NGX_ERROR);

    ngx_test_null(change_index,
                  ngx_alloc(sizeof(ngx_event_t *) * dpcf->changes, log),
                  NGX_ERROR);

    if (ngx_event_timer_init(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_event_actions = ngx_devpoll_module_ctx.actions;
    ngx_event_flags = NGX_HAVE_LEVEL_EVENT|NGX_USE_LEVEL_EVENT;

    return NGX_OK;
}


static void ngx_devpoll_done(ngx_log_t *log)
{
    if (close(dp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "close(/dev/poll) failed");
    }

    ngx_event_timer_done(log);

    ngx_free(change_list);
    ngx_free(event_list);
    ngx_free(change_index);

}


static int ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags)
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
    return ngx_devpoll_set_event(ev, event, 0);
}


static int ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(c->log, "del event: %d, %d" _ c->fd _ event);
#endif

    if (ngx_devpoll_set_event(ev, POLLREMOVE, flags) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ev->active = 0;

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    /* we need to restore second event if it exists */

    c = ev->data;

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


static int ngx_devpoll_set_event(ngx_event_t *ev, int event, u_int flags)
{
    int                n;
    ngx_connection_t  *c;

    c = ev->data;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "devpoll fd:%d event:%d flush:%d" _
                           c->fd _ event _ flags);
#endif

    if (nchanges >= max_changes) {
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
    ngx_msec_t         timer, delta;
    ngx_err_t          err;
    ngx_connection_t  *c;
    struct dvpoll      dvp;
    struct timeval     tv;

    timer = ngx_event_find_timer();

    if (timer) {
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

    if ((int) timer != INFTIM) {
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;
        ngx_event_expire_timers(delta);

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
            c->read->event_handler(c->read);
        }

        if (event_list[i].revents & POLLOUT) {
            if (!c->write->active) {
                continue;
            }

            c->write->ready = 1;
            c->write->event_handler(c->write);
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

    return NGX_OK;
}


static void *ngx_devpoll_create_conf(ngx_pool_t *pool)
{
    ngx_devpoll_conf_t  *dpcf;

    ngx_test_null(dpcf, ngx_palloc(pool, sizeof(ngx_devpoll_conf_t)),
                  NGX_CONF_ERROR);

    dpcf->changes = NGX_CONF_UNSET;
    dpcf->events = NGX_CONF_UNSET;

    return dpcf;
}


static char *ngx_devpoll_init_conf(ngx_pool_t *pool, void *conf)
{
    ngx_devpoll_conf_t *dpcf = conf;

    ngx_conf_init_value(dpcf->changes, 512);
    ngx_conf_init_value(dpcf->events, 512);

    return NGX_CONF_OK;
}
