
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
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
    u_int  changes;
    u_int  events;
} ngx_devpoll_conf_t;


static int ngx_devpoll_init(ngx_cycle_t *cycle);
static void ngx_devpoll_done(ngx_cycle_t *cycle);
static int ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_devpoll_set_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_devpoll_process_events(ngx_log_t *log);

static void *ngx_devpoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_devpoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int              dp = -1;
static struct pollfd   *change_list, *event_list;
static u_int            nchanges, max_changes, nevents;

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
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static int ngx_devpoll_init(ngx_cycle_t *cycle)
{
    size_t               n;
    ngx_devpoll_conf_t  *dpcf;

    dpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_devpoll_module);

ngx_log_debug(cycle->log, "CH: %d" _ dpcf->changes);
ngx_log_debug(cycle->log, "EV: %d" _ dpcf->events);

    if (dp == -1) {
        dp = open("/dev/poll", O_RDWR);

        if (dp == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "open(/dev/poll) failed");
            return NGX_ERROR;
        }
    }

    if (max_changes < dpcf->changes) {
        if (nchanges) {
            n = nchanges * sizeof(struct pollfd);
            if ((size_t) write(dp, change_list, n) != n) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "write(/dev/poll) failed");
                return NGX_ERROR;
            }

            nchanges = 0;
        }

        if (change_list) {
            ngx_free(change_list);
        }

        ngx_test_null(change_list,
                      ngx_alloc(sizeof(struct pollfd) * dpcf->changes,
                                cycle->log),
                      NGX_ERROR);

        if (change_index) {
            ngx_free(change_index);
        }

        ngx_test_null(change_index,
                      ngx_alloc(sizeof(ngx_event_t *) * dpcf->changes,
                                cycle->log),
                      NGX_ERROR);
    }

    max_changes = dpcf->changes;

    if (nevents < dpcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        ngx_test_null(event_list,
                      ngx_alloc(sizeof(struct pollfd) * dpcf->events,
                                cycle->log),
                      NGX_ERROR);
    }

    nevents = dpcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_devpoll_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT;

    return NGX_OK;
}


static void ngx_devpoll_done(ngx_cycle_t *cycle)
{
    if (close(dp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close(/dev/poll) failed");
    }

    dp = -1;

    ngx_free(change_list);
    ngx_free(event_list);
    ngx_free(change_index);

    change_list = NULL;
    event_list = NULL;
    change_index = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
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

    c = ev->data;

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

    /* we need to restore the second event if it exists */

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
    size_t             n;
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
        if ((size_t) write(dp, change_list, n) != n) {
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
        if ((size_t) write(dp, change_list, n) != n) {
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
    int                 events, i, j;
    size_t              n;
    ngx_msec_t          timer;
    ngx_err_t           err;
    ngx_cycle_t       **cycle;
    ngx_epoch_msec_t   delta;
    ngx_connection_t   *c;
    struct dvpoll       dvp;
    struct timeval      tv;

    timer = ngx_event_find_timer();

    if (timer) {
        ngx_gettimeofday(&tv);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    } else {
        timer = (ngx_msec_t) INFTIM;
        delta = 0;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "devpoll timer: %d" _ timer);
#endif

    if (nchanges) {
        n = nchanges * sizeof(struct pollfd);
        if ((size_t) write(dp, change_list, n) != n) {
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
        err = ngx_errno;
    } else {
        err = 0;
    }

    nchanges = 0;

    ngx_gettimeofday(&tv);

    if (ngx_cached_time != tv.tv_sec) {
        ngx_cached_time = tv.tv_sec;
        ngx_time_update();
    }

    if ((int) timer != INFTIM) {
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "devpoll timer: %d, delta: %d" _ timer _ (int)delta);
#endif
        ngx_event_expire_timers((ngx_msec_t) delta);

    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "ioctl(DP_POLL) returned no events without timeout");
            return NGX_ERROR;
        }

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "devpoll timer: %d, delta: %d" _ timer _ (int)delta);
#endif
    }

    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "ioctl(DP_POLL) failed");
        return NGX_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = &ngx_cycle->connections[event_list[i].fd];

        if (c->fd == -1) {
            cycle = ngx_old_cycles.elts;
            for (j = 0; j < ngx_old_cycles.nelts; j++) {
                if (cycle[i] == NULL) {
                    continue;
                }
                c = &cycle[j]->connections[event_list[i].fd];
                if (c->fd != -1) {
                    break;
                }
            }
        }

        if (c->fd == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "unkonwn cycle");
            exit(1);
        }

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "devpoll: %d: ev:%d rev:%d" _
                      event_list[i].fd _
                      event_list[i].events _ event_list[i].revents);
#endif

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


static void *ngx_devpoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_devpoll_conf_t  *dpcf;

    ngx_test_null(dpcf, ngx_palloc(cycle->pool, sizeof(ngx_devpoll_conf_t)),
                  NGX_CONF_ERROR);

    dpcf->changes = NGX_CONF_UNSET;
    dpcf->events = NGX_CONF_UNSET;

    return dpcf;
}


static char *ngx_devpoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_devpoll_conf_t *dpcf = conf;

    ngx_conf_init_unsigned_value(dpcf->changes, 512);
    ngx_conf_init_unsigned_value(dpcf->events, 512);

    return NGX_CONF_OK;
}
