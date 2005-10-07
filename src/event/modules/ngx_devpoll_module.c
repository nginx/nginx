
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_DEVPOLL)

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


static ngx_int_t ngx_devpoll_init(ngx_cycle_t *cycle);
static void ngx_devpoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_devpoll_set_event(ngx_event_t *ev, int event, u_int flags);
static ngx_int_t ngx_devpoll_process_events(ngx_cycle_t *cycle);

static void *ngx_devpoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_devpoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int              dp = -1;
static struct pollfd   *change_list, *event_list;
static u_int            nchanges, max_changes, nevents;

static ngx_event_t    **change_index;


static ngx_str_t      devpoll_name = ngx_string("/dev/poll");

static ngx_command_t  ngx_devpoll_commands[] = {

    { ngx_string("devpoll_changes"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_devpoll_conf_t, changes),
      NULL },

    { ngx_string("devpoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_devpoll_conf_t, events),
      NULL },

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
        NULL,                              /* process the changes */
        ngx_devpoll_process_events,        /* process the events */
        ngx_devpoll_init,                  /* init the events */
        ngx_devpoll_done,                  /* done the events */
    }

};

ngx_module_t  ngx_devpoll_module = {
    NGX_MODULE_V1,
    &ngx_devpoll_module_ctx,               /* module context */
    ngx_devpoll_commands,                  /* module directives */
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
ngx_devpoll_init(ngx_cycle_t *cycle)
{
    size_t               n;
    ngx_devpoll_conf_t  *dpcf;

    dpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_devpoll_module);

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
            if (write(dp, change_list, n) != (ssize_t) n) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "write(/dev/poll) failed");
                return NGX_ERROR;
            }

            nchanges = 0;
        }

        if (change_list) {
            ngx_free(change_list);
        }

        change_list = ngx_alloc(sizeof(struct pollfd) * dpcf->changes,
                                cycle->log);
        if (change_list == NULL) {
            return NGX_ERROR;
        }

        if (change_index) {
            ngx_free(change_index);
        }

        change_index = ngx_alloc(sizeof(ngx_event_t *) * dpcf->changes,
                                 cycle->log);
        if (change_index == NULL) {
            return NGX_ERROR;
        }
    }

    max_changes = dpcf->changes;

    if (nevents < dpcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(sizeof(struct pollfd) * dpcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = dpcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_devpoll_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT|NGX_USE_FD_EVENT;

    return NGX_OK;
}


static void
ngx_devpoll_done(ngx_cycle_t *cycle)
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


static ngx_int_t
ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags)
{
#if (NGX_DEBUG)
    ngx_connection_t *c;
#endif

#if (NGX_READ_EVENT != POLLIN)
    event = (event == NGX_READ_EVENT) ? POLLIN : POLLOUT;
#endif

#if (NGX_DEBUG)
    c = ev->data;
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll add event: fd:%d ev:%04Xd", c->fd, event);
#endif

    ev->active = 1;

    return ngx_devpoll_set_event(ev, event, 0);
}


static ngx_int_t
ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = ev->data;

#if (NGX_READ_EVENT != POLLIN)
    event = (event == NGX_READ_EVENT) ? POLLIN : POLLOUT;
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll del event: fd:%d ev:%04Xd", c->fd, event);

    if (ngx_devpoll_set_event(ev, POLLREMOVE, flags) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ev->active = 0;

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    /* restore the paired event if it exists */

    if (event == POLLIN) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e && e->active) {
        return ngx_devpoll_set_event(e, event, 0);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_devpoll_set_event(ngx_event_t *ev, int event, u_int flags)
{
    size_t             n;
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll fd:%d ev:%04Xd fl:%04Xd", c->fd, event, flags);

    if (nchanges >= max_changes) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "/dev/pool change list is filled up");

        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
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
        if (write(dp, change_list, n) != (ssize_t) n) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "write(/dev/poll) failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    return NGX_OK;
}


ngx_int_t
ngx_devpoll_process_events(ngx_cycle_t *cycle)
{
    int                 events, revents;
    size_t              n;
    ngx_err_t           err;
    ngx_int_t           i;
    ngx_uint_t          lock, accept_lock;
    ngx_msec_t          timer, delta;
#if 0
    ngx_cycle_t       **old_cycle;
#endif
    ngx_event_t        *rev, *wev;
    ngx_connection_t   *c;
    struct dvpoll       dvp;
    struct timeval      tv;

    timer = ngx_event_find_timer();

    /* NGX_TIMER_INFINITE == INFTIM */

    accept_lock = 0;

    if (ngx_accept_mutex) {
        if (ngx_accept_disabled > 0) {
            ngx_accept_disabled--;

        } else {
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                return NGX_ERROR;
            } 

            if (ngx_accept_mutex_held) {
                accept_lock = 1;

            } else if (timer == NGX_TIMER_INFINITE
                       || timer > ngx_accept_mutex_delay)
            {
                timer = ngx_accept_mutex_delay;
            }
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "devpoll timer: %M", timer);

    if (nchanges) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "write(/dev/poll) failed");
            ngx_accept_mutex_unlock();
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
    ngx_time_update(tv.tv_sec);

    delta = ngx_current_time;
    ngx_current_time = (ngx_msec_t) tv.tv_sec * 1000 + tv.tv_usec / 1000;

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "ioctl(DP_POLL) failed");
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }

    if (timer != NGX_TIMER_INFINITE) {
        delta = ngx_current_time - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "devpoll timer: %M, delta: %M", timer, delta);
    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "ioctl(DP_POLL) returned no events without timeout");
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        }
    }

    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }

    lock = 1;

    for (i = 0; i < events; i++) {
        c = ngx_cycle->files[event_list[i].fd];

        if (c->fd == -1) {
            if (c->read->closed) {
                continue;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "unexpected event");
            continue;
        }

        revents = event_list[i].revents;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "devpoll: fd:%d, ev:%04Xd, rev:%04Xd",
                       event_list[i].fd, event_list[i].events, revents);

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "ioctl(DP_POLL) error fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange ioctl(DP_POLL) events "
                          "fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if ((revents & (POLLERR|POLLHUP|POLLNVAL))
             && (revents & (POLLIN|POLLOUT)) == 0)
        {
            /*
             * if the error events were returned without POLLIN or POLLOUT,
             * then add these flags to handle the events at least in one
             * active handler 
             */

            revents |= POLLIN|POLLOUT;
        }

        wev = c->write;

        if ((revents & POLLOUT) && wev->active) {
            wev->ready = 1;

            if (!ngx_threaded && !ngx_accept_mutex_held) {
                wev->handler(wev);

            } else {
                ngx_post_event(wev);
            }
        }

        /*
         * POLLIN must be handled after POLLOUT because we use
         * the optimization to avoid the unnecessary mutex locking/unlocking
         * if the accept event is the last one.
         */

        rev = c->read;

        if ((revents & POLLIN) && rev->active) {
            rev->ready = 1;

            if (!ngx_threaded && !ngx_accept_mutex_held) {
                rev->handler(rev);

            } else if (!rev->accept) {
                ngx_post_event(rev);

            } else if (ngx_accept_disabled <= 0) {
                ngx_mutex_unlock(ngx_posted_events_mutex);

                c->read->handler(rev);

                if (ngx_accept_disabled > 0) { 
                    ngx_accept_mutex_unlock();
                    accept_lock = 0;
                }

                if (i + 1 == events) {
                    lock = 0;
                    break;
                }

                if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                    if (accept_lock) {
                        ngx_accept_mutex_unlock();
                    }
                    return NGX_ERROR;
                }
            }
        }
    }

    if (accept_lock) {
        ngx_accept_mutex_unlock();
    }

    if (lock) {
        ngx_mutex_unlock(ngx_posted_events_mutex);
    }

    ngx_event_expire_timers();

    if (!ngx_threaded) {
        ngx_event_process_posted(cycle);
    }

    return NGX_OK;
}


static void *
ngx_devpoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_devpoll_conf_t  *dpcf;

    dpcf = ngx_palloc(cycle->pool, sizeof(ngx_devpoll_conf_t));
    if (dpcf == NULL) {
        return NGX_CONF_ERROR;
    }

    dpcf->changes = NGX_CONF_UNSET;
    dpcf->events = NGX_CONF_UNSET;

    return dpcf;
}


static char *
ngx_devpoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_devpoll_conf_t *dpcf = conf;

    ngx_conf_init_unsigned_value(dpcf->changes, 32);
    ngx_conf_init_unsigned_value(dpcf->events, 32);

    return NGX_CONF_OK;
}
