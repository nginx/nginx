
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400
#define EPOLLERR       0x008
#define EPOLLHUP       0x010

#define EPOLLET        0x80000000
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};

int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_create(int size)
{
    return -1;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#endif


typedef struct {
    u_int  events;
} ngx_epoll_conf_t;


static int ngx_epoll_init(ngx_cycle_t *cycle);
static void ngx_epoll_done(ngx_cycle_t *cycle);
static int ngx_epoll_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_epoll_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_epoll_add_connection(ngx_connection_t *c);
static int ngx_epoll_del_connection(ngx_connection_t *c);
static int ngx_epoll_process_events(ngx_log_t *log);

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static u_int                nevents;


static ngx_str_t      epoll_name = ngx_string("epoll");

static ngx_command_t  ngx_epoll_commands[] = {

    {ngx_string("epoll_events"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_epoll_conf_t, events),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */

    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
        ngx_epoll_process_events,        /* process the events */
        ngx_epoll_init,                  /* init the events */
        ngx_epoll_done,                  /* done the events */
    }
};

ngx_module_t  ngx_epoll_module = {
    NGX_MODULE,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static int ngx_epoll_init(ngx_cycle_t *cycle)
{
    size_t             n;
    ngx_event_conf_t  *ecf;
    ngx_epoll_conf_t  *epcf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    if (ep == -1) {
        ep = epoll_create(ecf->connections / 2);

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }
    }

    if (nevents < epcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = epcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_epoll_module_ctx.actions;

    ngx_event_flags = NGX_USE_EDGE_EVENT;

    return NGX_OK;
}


static void ngx_epoll_done(ngx_cycle_t *cycle)
{
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static int ngx_epoll_add_event(ngx_event_t *ev, int event, u_int flags)
{
    struct epoll_event   ee;
    ngx_connection_t    *c;

    c = ev->data;

#if (NGX_READ_EVENT != EPOLLIN) || (NGX_WRITE_EVENT != EPOLLOUT)
    if (event == NGX_READ_EVENT) {
        event = EPOLLIN;

    } else {
        event = EPOLLOUT;
    }
#endif

    ee.events = event|EPOLLET;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add event: fd:%d ev:%08X", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_MOD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    ev->active = 1;

    return NGX_OK;
}


static int ngx_epoll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    struct epoll_event   ee;
    ngx_connection_t    *c;

    c = ev->data;

    ee.events = 0;
    ee.data.ptr = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del event: fd:%d", c->fd);

    if (epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_MOD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    ev->active = 0;

    return NGX_OK;
}


static int ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08X", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


static int ngx_epoll_del_connection(ngx_connection_t *c)
{
    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


int ngx_epoll_process_events(ngx_log_t *log)
{
    int                 events;
    ngx_int_t           instance, i;
    size_t              n;
    ngx_msec_t          timer;
    ngx_err_t           err;
    ngx_cycle_t       **cycle;
    struct timeval      tv;
    ngx_connection_t   *c;
    ngx_epoch_msec_t    delta;


    timer = ngx_event_find_timer();
    ngx_old_elapsed_msec = ngx_elapsed_msec;

    if (timer == 0) {
        timer = (ngx_msec_t) -1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "epoll timer: %d", timer);

    events = epoll_wait(ep, event_list, nevents, timer);

    if (events == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ngx_start_msec;

    if (timer != (ngx_msec_t) -1) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "epoll timer: %d, delta: %d", timer, (int) delta);
    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "epoll_wait() returned no events without timeout");
            return NGX_ERROR;
        }
    }

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                       "epoll: fd:%d ev:%04X d:" PTR_FMT,
                       c->fd, event_list[i].events, event_list[i].data);

        if (c->read->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                           "epoll: stale event " PTR_FMT, c);
            continue;
        }

        if (event_list[i].events & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                           "epoll_wait() error on fd:%d ev:%04X",
                           c->fd, event_list[i].events);
        }

        if (event_list[i].events & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "strange epoll_wait() events fd:%d ev:%04X",
                          c->fd, event_list[i].events);
        }

        if ((event_list[i].events & (EPOLLIN|EPOLLERR|EPOLLHUP))
            && c->read->active)
        {
            c->read->ready = 1;
            c->read->event_handler(c->read);
        }

        if ((event_list[i].events & (EPOLLOUT|EPOLLERR|EPOLLHUP))
            && c->write->active)
        {
            c->write->ready = 1;
            c->write->event_handler(c->write);
        }
    }

    if (timer != (ngx_msec_t) -1 && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    return NGX_OK;
}


static void *ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    ngx_test_null(epcf, ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t)),
                  NGX_CONF_ERROR);

    epcf->events = NGX_CONF_UNSET;

    return epcf;
}


static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    ngx_conf_init_unsigned_value(epcf->events, 512);

    return NGX_CONF_OK;
}
