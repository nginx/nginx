
/*
 * Copyright (C) 2002-2003 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_kqueue_module.h>


typedef struct {
    int  changes;
    int  events;
} ngx_kqueue_conf_t;


static int ngx_kqueue_init(ngx_cycle_t *cycle);
static void ngx_kqueue_done(ngx_cycle_t *cycle);
static int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags);
static int ngx_kqueue_process_events(ngx_log_t *log);

static void *ngx_kqueue_create_conf(ngx_cycle_t *cycle);
static char *ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf);


int                    ngx_kqueue = -1;

static struct kevent  *change_list, *event_list;
static int             max_changes, nchanges, nevents;


static ngx_str_t      kqueue_name = ngx_string("kqueue");

static ngx_command_t  ngx_kqueue_commands[] = {

    {ngx_string("kqueue_changes"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_kqueue_conf_t, changes),
     NULL},

    {ngx_string("kqueue_events"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_kqueue_conf_t, events),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_kqueue_module_ctx = {
    &kqueue_name,
    ngx_kqueue_create_conf,                /* create configuration */
    ngx_kqueue_init_conf,                  /* init configuration */

    {
        ngx_kqueue_add_event,              /* add an event */
        ngx_kqueue_del_event,              /* delete an event */
        ngx_kqueue_add_event,              /* enable an event */
        ngx_kqueue_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        ngx_kqueue_process_events,         /* process the events */
        ngx_kqueue_init,                   /* init the events */
        ngx_kqueue_done                    /* done the events */
    }

};

ngx_module_t  ngx_kqueue_module = {
    NGX_MODULE,
    &ngx_kqueue_module_ctx,                /* module context */
    ngx_kqueue_commands,                   /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};



static int ngx_kqueue_init(ngx_cycle_t *cycle)
{
    struct timespec     ts;
    ngx_kqueue_conf_t  *kcf;

    kcf = ngx_event_get_conf(cycle->conf_ctx, ngx_kqueue_module);

ngx_log_debug(cycle->log, "CH: %d" _ kcf->changes);
ngx_log_debug(cycle->log, "EV: %d" _ kcf->events);

    if (ngx_kqueue == -1) {
        ngx_kqueue = kqueue();

        if (ngx_kqueue == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "kqueue() failed");
            return NGX_ERROR;
        }
    }

    if (max_changes < kcf->changes) {
        if (nchanges) {
            ts.tv_sec = 0;
            ts.tv_nsec = 0;

            if (kevent(ngx_kqueue, change_list, nchanges, NULL, 0, &ts) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "kevent() failed");
                return NGX_ERROR;
            }
            nchanges = 0;
        }

        if (change_list) {
            ngx_free(change_list);
        }

        ngx_test_null(change_list,
                      ngx_alloc(kcf->changes * sizeof(struct kevent),
                                cycle->log),
                      NGX_ERROR);
    }

    max_changes = kcf->changes;

    if (nevents < kcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        ngx_test_null(event_list,
                      ngx_alloc(kcf->events * sizeof(struct kevent),
                                cycle->log),
                      NGX_ERROR);
    }

    nevents = kcf->events;

    if (ngx_event_timer_init(cycle) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_kqueue_module_ctx.actions;

    ngx_event_flags = NGX_USE_ONESHOT_EVENT
#if (HAVE_CLEAR_EVENT)
                     |NGX_USE_CLEAR_EVENT
#else
                     |NGX_USE_LEVEL_EVENT
#endif
#if (HAVE_LOWAT_EVENT)
                     |NGX_HAVE_LOWAT_EVENT
#endif
                     |NGX_HAVE_KQUEUE_EVENT;

    return NGX_OK;
}


static void ngx_kqueue_done(ngx_cycle_t *cycle)
{
    if (close(ngx_kqueue) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "kqueue close() failed");
    }

    ngx_kqueue = -1;

    ngx_event_timer_done(cycle);

    ngx_free(change_list);
    ngx_free(event_list);

    change_list = NULL;
    event_list = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    if (nchanges > 0
        && ev->index < (u_int) nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
                                                             == (uintptr_t) ev)
    {
        c = ev->data;
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "previous event on #%d were not passed in kernel", c->fd);

        return NGX_ERROR;
    }

    return ngx_kqueue_set_event(ev, event, EV_ADD|flags);
}


static int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t  *e;

    ev->active = 0;

    if (nchanges > 0
        && ev->index < (u_int) nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
                                                             == (uintptr_t) ev)
    {
#if (NGX_DEBUG_EVENT)
        ngx_connection_t *c = (ngx_connection_t *) ev->data;
        ngx_log_debug(ev->log, "kqueue event deleted: %d: ft:%d" _
                      c->fd _ event);
#endif

        /* if the event is still not passed to a kernel we will not pass it */

        if (ev->index < (u_int) --nchanges) {
            e = (ngx_event_t *) change_list[nchanges].udata;
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NGX_OK;
    }

    /*
     * when the file descriptor is closed a kqueue automatically deletes
     * its filters so we do not need to delete explicity the event
     * before the closing the file descriptor.
     */

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    return ngx_kqueue_set_event(ev, event,
                           flags & NGX_DISABLE_EVENT ? EV_DISABLE : EV_DELETE);
}


static int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags)
{
    struct timespec    ts;
    ngx_connection_t  *c;

    c = ev->data;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "kqueue set event: %d: ft:%d fl:%08x" _
                  c->fd _ filter _ flags);
#endif

    if (nchanges >= max_changes) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(ngx_kqueue, change_list, nchanges, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent() failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].ident = c->fd;
    change_list[nchanges].filter = filter;
    change_list[nchanges].flags = flags;
    change_list[nchanges].udata = (void *) ((uintptr_t) ev | ev->instance);

#if (HAVE_LOWAT_EVENT)

    if (flags & NGX_LOWAT_EVENT) {
        change_list[nchanges].fflags = NOTE_LOWAT;
        change_list[nchanges].data = ev->available;

    } else {
        change_list[nchanges].fflags = 0;
        change_list[nchanges].data = 0;
    }

#else

    change_list[nchanges].fflags = 0;
    change_list[nchanges].data = 0;

#endif

    ev->index = nchanges;

    nchanges++;

    return NGX_OK;
}


static int ngx_kqueue_process_events(ngx_log_t *log)
{
    int                events, instance, i;
    ngx_err_t          err;
    ngx_msec_t         timer;
    ngx_event_t       *ev;
    ngx_epoch_msec_t   delta;
    struct timeval     tv;
    struct timespec    ts, *tp;

    timer = ngx_event_find_timer();

    if (timer) {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;

        ngx_gettimeofday(&tv);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    } else {
        delta = 0;
        tp = NULL;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "kevent timer: %d" _ timer);
#endif

    events = kevent(ngx_kqueue, change_list, nchanges, event_list, nevents, tp);

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

    if (timer) {
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "kevent timer: %d, delta: %d" _ timer _ (int) delta);
#endif

        /*
         * The expired timers must be handled before a processing of the events
         * because the new timers can be added during a processing
         */

        ngx_event_expire_timers((ngx_msec_t) delta);

    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "kevent() returned no events without timeout");
            return NGX_ERROR;
        }

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(log, "kevent timer: %d, delta: %d" _ timer _ (int) delta);
#endif
    }

    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "kevent() failed");
        return NGX_ERROR;
    }

    for (i = 0; i < events; i++) {

#if (NGX_DEBUG_EVENT)
        if (event_list[i].ident > 0x8000000
            && event_list[i].ident != (unsigned) -1)
        {
            ngx_log_debug(log,
                          "kevent: %08x: ft:%d fl:%08x ff:%08x d:%d ud:%08x" _
                          event_list[i].ident _ event_list[i].filter _
                          event_list[i].flags _ event_list[i].fflags _
                          event_list[i].data _ event_list[i].udata);
        } else {
            ngx_log_debug(log,
                          "kevent: %d: ft:%d fl:%08x ff:%08x d:%d ud:%08x" _
                          event_list[i].ident _ event_list[i].filter _
                          event_list[i].flags _ event_list[i].fflags _
                          event_list[i].data _ event_list[i].udata);
        }
#endif

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, event_list[i].data,
                          "kevent() error on %d", event_list[i].ident);
            continue;
        }

        ev = (ngx_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (ngx_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            /*
             * it's a stale event from a file descriptor
             * that was just closed in this iteration
             */

            if (ev->active == 0 || ev->instance != instance) {
                ngx_log_debug(log, "stale kevent");
                continue;
            }

            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->kq_eof = 1;
                ev->kq_errno = event_list[i].fflags;
            }

            if (ev->oneshot && ev->timer_set) {
                ngx_del_timer(ev);
            }

            ev->ready = 1;

            ev->event_handler(ev);

            break;

        case EVFILT_AIO:
            ev->complete = 1;
            ev->ready = 1;

            ev->event_handler(ev);

            break;


        default:
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "unexpected kevent filter %d" _ event_list[i].filter);
        }
    }

    return NGX_OK;
}


static void *ngx_kqueue_create_conf(ngx_cycle_t *cycle)
{
    ngx_kqueue_conf_t  *kcf;

    ngx_test_null(kcf, ngx_palloc(cycle->pool, sizeof(ngx_kqueue_conf_t)),
                  NGX_CONF_ERROR);

    kcf->changes = NGX_CONF_UNSET;
    kcf->events = NGX_CONF_UNSET;

    return kcf;
}


static char *ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_kqueue_conf_t *kcf = conf;

    ngx_conf_init_value(kcf->changes, 512);
    ngx_conf_init_value(kcf->events, 512);

    return NGX_CONF_OK;
}
