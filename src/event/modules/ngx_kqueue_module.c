
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_uint_t  changes;
    ngx_uint_t  events;
} ngx_kqueue_conf_t;


static ngx_int_t ngx_kqueue_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_kqueue_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_kqueue_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_kqueue_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_kqueue_set_event(ngx_event_t *ev, ngx_int_t filter,
    ngx_uint_t flags);
static ngx_int_t ngx_kqueue_process_changes(ngx_cycle_t *cycle, ngx_uint_t try);
static ngx_int_t ngx_kqueue_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);
static ngx_inline void ngx_kqueue_dump_event(ngx_log_t *log,
    struct kevent *kev);

static void *ngx_kqueue_create_conf(ngx_cycle_t *cycle);
static char *ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf);


int                    ngx_kqueue = -1;

/*
 * The "change_list" should be declared as ngx_thread_volatile.
 * However, the use of the change_list is localized in kqueue functions and
 * is protected by the mutex so even the "icc -ipo" should not build the code
 * with the race condition.  Thus we avoid the declaration to make a more
 * readable code.
 */

static struct kevent  *change_list, *change_list0, *change_list1;
static struct kevent  *event_list;
static ngx_uint_t      max_changes, nchanges, nevents;

#if (NGX_THREADS)
static ngx_mutex_t    *list_mutex;
static ngx_mutex_t    *kevent_mutex;
#endif



static ngx_str_t      kqueue_name = ngx_string("kqueue");

static ngx_command_t  ngx_kqueue_commands[] = {

    { ngx_string("kqueue_changes"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_kqueue_conf_t, changes),
      NULL },

    { ngx_string("kqueue_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_kqueue_conf_t, events),
      NULL },

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
        ngx_kqueue_process_changes,        /* process the changes */
        ngx_kqueue_process_events,         /* process the events */
        ngx_kqueue_init,                   /* init the events */
        ngx_kqueue_done                    /* done the events */
    }

};

ngx_module_t  ngx_kqueue_module = {
    NGX_MODULE_V1,
    &ngx_kqueue_module_ctx,                /* module context */
    ngx_kqueue_commands,                   /* module directives */
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
ngx_kqueue_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_kqueue_conf_t  *kcf;
    struct timespec     ts;
#if (NGX_HAVE_TIMER_EVENT)
    struct kevent       kev;
#endif

    kcf = ngx_event_get_conf(cycle->conf_ctx, ngx_kqueue_module);

    if (ngx_kqueue == -1) {
        ngx_kqueue = kqueue();

        if (ngx_kqueue == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "kqueue() failed");
            return NGX_ERROR;
        }

#if (NGX_THREADS)

        list_mutex = ngx_mutex_init(cycle->log, 0);
        if (list_mutex == NULL) {
            return NGX_ERROR;
        }

        kevent_mutex = ngx_mutex_init(cycle->log, 0);
        if (kevent_mutex == NULL) {
            return NGX_ERROR;
        }

#endif
    }

    if (max_changes < kcf->changes) {
        if (nchanges) {
            ts.tv_sec = 0;
            ts.tv_nsec = 0;

            if (kevent(ngx_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
                == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "kevent() failed");
                return NGX_ERROR;
            }
            nchanges = 0;
        }

        if (change_list0) {
            ngx_free(change_list0);
        }

        change_list0 = ngx_alloc(kcf->changes * sizeof(struct kevent),
                                 cycle->log);
        if (change_list0 == NULL) {
            return NGX_ERROR;
        }

        if (change_list1) {
            ngx_free(change_list1);
        }

        change_list1 = ngx_alloc(kcf->changes * sizeof(struct kevent),
                                 cycle->log);
        if (change_list1 == NULL) {
            return NGX_ERROR;
        }

        change_list = change_list0;
    }

    max_changes = kcf->changes;

    if (nevents < kcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(kcf->events * sizeof(struct kevent), cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    ngx_event_flags = NGX_USE_ONESHOT_EVENT
                      |NGX_USE_KQUEUE_EVENT
                      |NGX_USE_VNODE_EVENT;

#if (NGX_HAVE_TIMER_EVENT)

    if (timer) {
        kev.ident = 0;
        kev.filter = EVFILT_TIMER;
        kev.flags = EV_ADD|EV_ENABLE;
        kev.fflags = 0;
        kev.data = timer;
        kev.udata = 0;

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(ngx_kqueue, &kev, 1, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kevent(EVFILT_TIMER) failed");
            return NGX_ERROR;
        }

        ngx_event_flags |= NGX_USE_TIMER_EVENT;
    }

#endif

#if (NGX_HAVE_CLEAR_EVENT)
    ngx_event_flags |= NGX_USE_CLEAR_EVENT;
#else
    ngx_event_flags |= NGX_USE_LEVEL_EVENT;
#endif

#if (NGX_HAVE_LOWAT_EVENT)
    ngx_event_flags |= NGX_USE_LOWAT_EVENT;
#endif

    nevents = kcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_kqueue_module_ctx.actions;

    return NGX_OK;
}


static void
ngx_kqueue_done(ngx_cycle_t *cycle)
{
    if (close(ngx_kqueue) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "kqueue close() failed");
    }

    ngx_kqueue = -1;

#if (NGX_THREADS)
    ngx_mutex_destroy(kevent_mutex);
    ngx_mutex_destroy(list_mutex);
#endif

    ngx_free(change_list1);
    ngx_free(change_list0);
    ngx_free(event_list);

    change_list1 = NULL;
    change_list0 = NULL;
    change_list = NULL;
    event_list = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static ngx_int_t
ngx_kqueue_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_int_t          rc;
#if 0
    ngx_event_t       *e;
    ngx_connection_t  *c;
#endif

    ev->active = 1;
    ev->disabled = 0;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    ngx_mutex_lock(list_mutex);

#if 0

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        if (change_list[ev->index].flags == EV_DISABLE) {

            /*
             * if the EV_DISABLE is still not passed to a kernel
             * we will not pass it
             */

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "kevent activated: %d: ft:%i",
                           ngx_event_ident(ev->data), event);

            if (ev->index < --nchanges) {
                e = (ngx_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
                change_list[ev->index] = change_list[nchanges];
                e->index = ev->index;
            }

            ngx_mutex_unlock(list_mutex);

            return NGX_OK;
        }

        c = ev->data;

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "previous event on #%d were not passed in kernel", c->fd);

        ngx_mutex_unlock(list_mutex);

        return NGX_ERROR;
    }

#endif

    rc = ngx_kqueue_set_event(ev, event, EV_ADD|EV_ENABLE|flags);

    ngx_mutex_unlock(list_mutex);

    return rc;
}


static ngx_int_t
ngx_kqueue_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_int_t     rc;
    ngx_event_t  *e;

    ev->active = 0;
    ev->disabled = 0;

    ngx_mutex_lock(list_mutex);

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "kevent deleted: %d: ft:%i",
                       ngx_event_ident(ev->data), event);

        /* if the event is still not passed to a kernel we will not pass it */

        nchanges--;

        if (ev->index < nchanges) {
            e = (ngx_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        ngx_mutex_unlock(list_mutex);

        return NGX_OK;
    }

    /*
     * when the file descriptor is closed the kqueue automatically deletes
     * its filters so we do not need to delete explicitly the event
     * before the closing the file descriptor.
     */

    if (flags & NGX_CLOSE_EVENT) {
        ngx_mutex_unlock(list_mutex);
        return NGX_OK;
    }

    if (flags & NGX_DISABLE_EVENT) {
        ev->disabled = 1;

    } else {
        flags |= EV_DELETE;
    }

    rc = ngx_kqueue_set_event(ev, event, flags);

    ngx_mutex_unlock(list_mutex);

    return rc;
}


static ngx_int_t
ngx_kqueue_set_event(ngx_event_t *ev, ngx_int_t filter, ngx_uint_t flags)
{
    struct kevent     *kev;
    struct timespec    ts;
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "kevent set event: %d: ft:%i fl:%04Xi",
                   c->fd, filter, flags);

    if (nchanges >= max_changes) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(ngx_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent() failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    kev = &change_list[nchanges];

    kev->ident = c->fd;
    kev->filter = (short) filter;
    kev->flags = (u_short) flags;
    kev->udata = NGX_KQUEUE_UDATA_T ((uintptr_t) ev | ev->instance);

    if (filter == EVFILT_VNODE) {
        kev->fflags = NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND
                                 |NOTE_ATTRIB|NOTE_RENAME
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500018
                                 |NOTE_REVOKE
#endif
                      ;
        kev->data = 0;

    } else {
#if (NGX_HAVE_LOWAT_EVENT)
        if (flags & NGX_LOWAT_EVENT) {
            kev->fflags = NOTE_LOWAT;
            kev->data = ev->available;

        } else {
            kev->fflags = 0;
            kev->data = 0;
        }
#else
        kev->fflags = 0;
        kev->data = 0;
#endif
    }

    ev->index = nchanges;
    nchanges++;

    if (flags & NGX_FLUSH_EVENT) {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "kevent flush");

        if (kevent(ngx_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent() failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kqueue_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int               events, n;
    ngx_int_t         i, instance;
    ngx_uint_t        level;
    ngx_err_t         err;
    ngx_event_t      *ev, **queue;
    struct timespec   ts, *tp;

    if (ngx_threaded) {
        if (ngx_kqueue_process_changes(cycle, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        n = 0;

    } else {
        n = (int) nchanges;
        nchanges = 0;
    }

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;

    } else {

        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;

        /*
         * 64-bit Darwin kernel has the bug: kernel level ts.tv_nsec is
         * the int32_t while user level ts.tv_nsec is the long (64-bit),
         * so on the big endian PowerPC all nanoseconds are lost.
         */

#if (NGX_DARWIN_KEVENT_BUG)
        ts.tv_nsec <<= 32;
#endif

        tp = &ts;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent timer: %M, changes: %d", timer, n);

    events = kevent(ngx_kqueue, change_list, n, event_list, (int) nevents, tp);

    err = (events == -1) ? ngx_errno : 0;

    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent events: %d", events);

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

        ngx_log_error(level, cycle->log, err, "kevent() failed");
        return NGX_ERROR;
    }

    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "kevent() returned no events without timeout");
        return NGX_ERROR;
    }

    for (i = 0; i < events; i++) {

        ngx_kqueue_dump_event(cycle->log, &event_list[i]);

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, event_list[i].data,
                          "kevent() error on %d filter:%d flags:%04Xd",
                          event_list[i].ident, event_list[i].filter,
                          event_list[i].flags);
            continue;
        }

#if (NGX_HAVE_TIMER_EVENT)

        if (event_list[i].filter == EVFILT_TIMER) {
            ngx_time_update();
            continue;
        }

#endif

        ev = (ngx_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (ngx_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "kevent: stale event %p", ev);
                continue;
            }

            if (ev->log && (ev->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
                ngx_kqueue_dump_event(ev->log, &event_list[i]);
            }

            if (ev->oneshot) {
                ev->active = 0;
            }

            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->pending_eof = 1;
                ev->kq_errno = event_list[i].fflags;
            }

            ev->ready = 1;

            break;

        case EVFILT_VNODE:
            ev->kq_vnode = 1;

            break;

        case EVFILT_AIO:
            ev->complete = 1;
            ev->ready = 1;

            break;

        default:
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "unexpected kevent() filter %d",
                          event_list[i].filter);
            continue;
        }

        if (flags & NGX_POST_EVENTS) {
            queue = ev->accept ? &ngx_posted_accept_events
                               : &ngx_posted_events;

            ngx_post_event(ev, queue);

            continue;
        }

        ev->handler(ev);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kqueue_process_changes(ngx_cycle_t *cycle, ngx_uint_t try)
{
    int               n;
    ngx_int_t         rc;
    ngx_err_t         err;
    struct timespec   ts;
    struct kevent    *changes;

    ngx_mutex_lock(kevent_mutex);

    ngx_mutex_lock(list_mutex);

    if (nchanges == 0) {
        ngx_mutex_unlock(list_mutex);
        ngx_mutex_unlock(kevent_mutex);
        return NGX_OK;
    }

    changes = change_list;
    if (change_list == change_list0) {
        change_list = change_list1;
    } else {
        change_list = change_list0;
    }

    n = (int) nchanges;
    nchanges = 0;

    ngx_mutex_unlock(list_mutex);

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent changes: %d", n);

    if (kevent(ngx_kqueue, changes, n, NULL, 0, &ts) == -1) {
        err = ngx_errno;
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "kevent() failed");
        rc = NGX_ERROR;

    } else {
        rc = NGX_OK;
    }

    ngx_mutex_unlock(kevent_mutex);

    return rc;
}


static ngx_inline void
ngx_kqueue_dump_event(ngx_log_t *log, struct kevent *kev)
{
    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, log, 0,
                   (kev->ident > 0x8000000 && kev->ident != (unsigned) -1) ?
                    "kevent: %p: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p":
                    "kevent: %d: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                    kev->ident, kev->filter,
                    kev->flags, kev->fflags,
                    kev->data, kev->udata);
}


static void *
ngx_kqueue_create_conf(ngx_cycle_t *cycle)
{
    ngx_kqueue_conf_t  *kcf;

    kcf = ngx_palloc(cycle->pool, sizeof(ngx_kqueue_conf_t));
    if (kcf == NULL) {
        return NULL;
    }

    kcf->changes = NGX_CONF_UNSET;
    kcf->events = NGX_CONF_UNSET;

    return kcf;
}


static char *
ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_kqueue_conf_t *kcf = conf;

    ngx_conf_init_uint_value(kcf->changes, 512);
    ngx_conf_init_uint_value(kcf->events, 512);

    return NGX_CONF_OK;
}
