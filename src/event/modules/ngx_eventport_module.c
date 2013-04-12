
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_EVENTPORT)

#define ushort_t  u_short
#define uint_t    u_int

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME          0
typedef int     clockid_t;
typedef void *  timer_t;
#endif

/* Solaris declarations */

#define PORT_SOURCE_AIO         1
#define PORT_SOURCE_TIMER       2
#define PORT_SOURCE_USER        3
#define PORT_SOURCE_FD          4
#define PORT_SOURCE_ALERT       5
#define PORT_SOURCE_MQ          6

#ifndef ETIME
#define ETIME                   64
#endif

#define SIGEV_PORT              4

typedef struct {
    int         portev_events;  /* event data is source specific */
    ushort_t    portev_source;  /* event source */
    ushort_t    portev_pad;     /* port internal use */
    uintptr_t   portev_object;  /* source specific object */
    void       *portev_user;    /* user cookie */
} port_event_t;

typedef struct  port_notify {
    int         portnfy_port;   /* bind request(s) to port */
    void       *portnfy_user;   /* user defined */
} port_notify_t;

#if (__FreeBSD_version < 700005)

typedef struct itimerspec {     /* definition per POSIX.4 */
    struct timespec it_interval;/* timer period */
    struct timespec it_value;   /* timer expiration */
} itimerspec_t;

#endif

int port_create(void);

int port_create(void)
{
    return -1;
}


int port_associate(int port, int source, uintptr_t object, int events,
    void *user);

int port_associate(int port, int source, uintptr_t object, int events,
    void *user)
{
    return -1;
}


int port_dissociate(int port, int source, uintptr_t object);

int port_dissociate(int port, int source, uintptr_t object)
{
    return -1;
}


int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout);

int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout)
{
    return -1;
}


int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid);

int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid)
{
    return -1;
}


int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue);

int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
    return -1;
}


int timer_delete(timer_t timerid);

int timer_delete(timer_t timerid)
{
    return -1;
}

#endif


typedef struct {
    ngx_uint_t  events;
} ngx_eventport_conf_t;


static ngx_int_t ngx_eventport_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_eventport_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_eventport_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_eventport_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_eventport_process_events(ngx_cycle_t *cycle,
    ngx_msec_t timer, ngx_uint_t flags);

static void *ngx_eventport_create_conf(ngx_cycle_t *cycle);
static char *ngx_eventport_init_conf(ngx_cycle_t *cycle, void *conf);

static int            ep = -1;
static port_event_t  *event_list;
static ngx_uint_t     nevents;
static timer_t        event_timer = (timer_t) -1;

static ngx_str_t      eventport_name = ngx_string("eventport");


static ngx_command_t  ngx_eventport_commands[] = {

    { ngx_string("eventport_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_eventport_conf_t, events),
      NULL },

      ngx_null_command
};


ngx_event_module_t  ngx_eventport_module_ctx = {
    &eventport_name,
    ngx_eventport_create_conf,             /* create configuration */
    ngx_eventport_init_conf,               /* init configuration */

    {
        ngx_eventport_add_event,           /* add an event */
        ngx_eventport_del_event,           /* delete an event */
        ngx_eventport_add_event,           /* enable an event */
        ngx_eventport_del_event,           /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* process the changes */
        ngx_eventport_process_events,      /* process the events */
        ngx_eventport_init,                /* init the events */
        ngx_eventport_done,                /* done the events */
    }

};

ngx_module_t  ngx_eventport_module = {
    NGX_MODULE_V1,
    &ngx_eventport_module_ctx,             /* module context */
    ngx_eventport_commands,                /* module directives */
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
ngx_eventport_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    port_notify_t          pn;
    struct itimerspec      its;
    struct sigevent        sev;
    ngx_eventport_conf_t  *epcf;

    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_eventport_module);

    if (ep == -1) {
        ep = port_create();

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "port_create() failed");
            return NGX_ERROR;
        }
    }

    if (nevents < epcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(sizeof(port_event_t) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    ngx_event_flags = NGX_USE_EVENTPORT_EVENT;

    if (timer) {
        ngx_memzero(&pn, sizeof(port_notify_t));
        pn.portnfy_port = ep;

        ngx_memzero(&sev, sizeof(struct sigevent));
        sev.sigev_notify = SIGEV_PORT;
#if !(NGX_TEST_BUILD_EVENTPORT)
        sev.sigev_value.sival_ptr = &pn;
#endif

        if (timer_create(CLOCK_REALTIME, &sev, &event_timer) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "timer_create() failed");
            return NGX_ERROR;
        }

        its.it_interval.tv_sec = timer / 1000;
        its.it_interval.tv_nsec = (timer % 1000) * 1000000;
        its.it_value.tv_sec = timer / 1000;
        its.it_value.tv_nsec = (timer % 1000) * 1000000;

        if (timer_settime(event_timer, 0, &its, NULL) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "timer_settime() failed");
            return NGX_ERROR;
        }

        ngx_event_flags |= NGX_USE_TIMER_EVENT;
    }

    nevents = epcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_eventport_module_ctx.actions;

    return NGX_OK;
}


static void
ngx_eventport_done(ngx_cycle_t *cycle)
{
    if (event_timer != (timer_t) -1) {
        if (timer_delete(event_timer) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "timer_delete() failed");
        }

        event_timer = (timer_t) -1;
    }

    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() event port failed");
    }

    ep = -1;

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static ngx_int_t
ngx_eventport_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_int_t          events, prev;
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = ev->data;

    events = event;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = POLLOUT;
#if (NGX_READ_EVENT != POLLIN)
        events = POLLIN;
#endif

    } else {
        e = c->read;
        prev = POLLIN;
#if (NGX_WRITE_EVENT != POLLOUT)
        events = POLLOUT;
#endif
    }

    if (e->oneshot) {
        events |= prev;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "eventport add event: fd:%d ev:%04Xi", c->fd, events);

    if (port_associate(ep, PORT_SOURCE_FD, c->fd, events,
                       (void *) ((uintptr_t) ev | ev->instance))
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "port_associate() failed");
        return NGX_ERROR;
    }

    ev->active = 1;
    ev->oneshot = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_eventport_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    /*
     * when the file descriptor is closed, the event port automatically
     * dissociates it from the port, so we do not need to dissociate explicitly
     * the event before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        ev->oneshot = 0;
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e->oneshot) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "eventport change event: fd:%d ev:%04Xi", c->fd, event);

        if (port_associate(ep, PORT_SOURCE_FD, c->fd, event,
                           (void *) ((uintptr_t) ev | ev->instance))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "port_associate() failed");
            return NGX_ERROR;
        }

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "eventport del event: fd:%d", c->fd);

        if (port_dissociate(ep, PORT_SOURCE_FD, c->fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "port_dissociate() failed");
            return NGX_ERROR;
        }
    }

    ev->active = 0;
    ev->oneshot = 0;

    return NGX_OK;
}


ngx_int_t
ngx_eventport_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int                 n, revents;
    u_int               events;
    ngx_err_t           err;
    ngx_int_t           instance;
    ngx_uint_t          i, level;
    ngx_event_t        *ev, *rev, *wev, **queue;
    ngx_connection_t   *c;
    struct timespec     ts, *tp;

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;

    } else {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventport timer: %M", timer);

    events = 1;

    n = port_getn(ep, event_list, (u_int) nevents, &events, tp);

    err = ngx_errno;

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update();
    }

    if (n == -1) {
        if (err == ETIME) {
            if (timer != NGX_TIMER_INFINITE) {
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "port_getn() returned no events without timeout");
            return NGX_ERROR;
        }

        level = (err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT;
        ngx_log_error(level, cycle->log, err, "port_getn() failed");
        return NGX_ERROR;
    }

    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "port_getn() returned no events without timeout");
        return NGX_ERROR;
    }

    ngx_mutex_lock(ngx_posted_events_mutex);

    for (i = 0; i < events; i++) {

        if (event_list[i].portev_source == PORT_SOURCE_TIMER) {
            ngx_time_update();
            continue;
        }

        ev = event_list[i].portev_user;

        switch (event_list[i].portev_source) {

        case PORT_SOURCE_FD:

            instance = (uintptr_t) ev & 1;
            ev = (ngx_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "eventport: stale event %p", ev);
                continue;
            }

            revents = event_list[i].portev_events;

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "eventport: fd:%d, ev:%04Xd",
                           event_list[i].portev_object, revents);

            if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "port_getn() error fd:%d ev:%04Xd",
                               event_list[i].portev_object, revents);
            }

            if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "strange port_getn() events fd:%d ev:%04Xd",
                              event_list[i].portev_object, revents);
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

            c = ev->data;
            rev = c->read;
            wev = c->write;

            rev->active = 0;
            wev->active = 0;

            if (revents & POLLIN) {

                if ((flags & NGX_POST_THREAD_EVENTS) && !rev->accept) {
                    rev->posted_ready = 1;

                } else {
                    rev->ready = 1;
                }

                if (flags & NGX_POST_EVENTS) {
                    queue = (ngx_event_t **) (rev->accept ?
                               &ngx_posted_accept_events : &ngx_posted_events);

                    ngx_locked_post_event(rev, queue);

                } else {
                    rev->handler(rev);

                    if (ev->closed || ev->instance != instance) {
                        continue;
                    }
                }

                if (rev->accept) {
                    if (ngx_use_accept_mutex) {
                        ngx_accept_events = 1;
                        continue;
                    }

                    if (port_associate(ep, PORT_SOURCE_FD, c->fd, POLLIN,
                                       (void *) ((uintptr_t) ev | ev->instance))
                        == -1)
                    {
                        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                                      "port_associate() failed");
                        return NGX_ERROR;
                    }
                }
            }

            if (revents & POLLOUT) {

                if (flags & NGX_POST_THREAD_EVENTS) {
                    wev->posted_ready = 1;

                } else {
                    wev->ready = 1;
                }

                if (flags & NGX_POST_EVENTS) {
                    ngx_locked_post_event(wev, &ngx_posted_events);

                } else {
                    wev->handler(wev);
                }
            }

            continue;

        default:
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "unexpected even_port object %d",
                          event_list[i].portev_object);
            continue;
        }
    }

    ngx_mutex_unlock(ngx_posted_events_mutex);

    return NGX_OK;
}


static void *
ngx_eventport_create_conf(ngx_cycle_t *cycle)
{
    ngx_eventport_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_eventport_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NGX_CONF_UNSET;

    return epcf;
}


static char *
ngx_eventport_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_eventport_conf_t *epcf = conf;

    ngx_conf_init_uint_value(epcf->events, 32);

    return NGX_CONF_OK;
}
