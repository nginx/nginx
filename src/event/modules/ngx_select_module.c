
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_time.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_select_module.h>


/* should be per-thread */
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
static ngx_event_t    timer_queue;
/* */

int ngx_select_init(int max_connections, ngx_log_t *log)
{
    if (max_connections > FD_SETSIZE) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
#if (WIN32)
                      "maximum number of descriptors "
                      "supported by select() is %d", FD_SETSIZE);
#else
                      "maximum descriptor number"
                      "supported by select() is %d", FD_SETSIZE - 1);
#endif
        exit(1);
    }

    FD_ZERO(&master_read_fd_set);
    FD_ZERO(&master_write_fd_set);

    ngx_test_null(event_index,
                  ngx_alloc(sizeof(ngx_event_t *) * 2 * max_connections, log),
                  NGX_ERROR);

    ngx_test_null(ready_index,
                  ngx_alloc(sizeof(ngx_event_t *) * 2 * max_connections, log),
                  NGX_ERROR);

    nevents = 0;

    timer_queue.timer_prev = &timer_queue;
    timer_queue.timer_next = &timer_queue;

    ngx_event_actions.add = ngx_select_add_event;
    ngx_event_actions.del = ngx_select_del_event;
    ngx_event_actions.timer = ngx_select_add_timer;
    ngx_event_actions.process = ngx_select_process_events;

#if (WIN32)
    max_read = max_write = 0;
#else
    max_fd = -1;
#endif

    return NGX_OK;
}

int ngx_select_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

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
    if (event == NGX_READ_EVENT)
        FD_SET(c->fd, &master_read_fd_set);

    else if (event == NGX_WRITE_EVENT)
        FD_SET(c->fd, &master_write_fd_set);

    if (max_fd != -1 && max_fd < c->fd)
        max_fd = c->fd;

#endif

    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NGX_OK;
}

int ngx_select_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t *c;
    c = (ngx_connection_t *) ev->data;

    if (ev->index == NGX_INVALID_INDEX)
        return NGX_OK;

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
    if (event == NGX_READ_EVENT)
        FD_CLR(c->fd, &master_read_fd_set);

    else if (event == NGX_WRITE_EVENT)
        FD_CLR(c->fd, &master_write_fd_set);

    if (max_fd == c->fd)
        max_fd = -1;
#endif

    if (ev->index < --nevents) {
        event_index[ev->index] = event_index[nevents];
        event_index[ev->index]->index = ev->index;
    }

    ev->active = 0;
    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}

int ngx_select_process_events(ngx_log_t *log)
{
    int                ready, found, nready;
    u_int              i, timer, delta;
    ngx_event_t       *ev;
    ngx_connection_t  *c;
    struct timeval     tv, *tp;

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;

    if (timer_queue.timer_next != &timer_queue) {
        timer = timer_queue.timer_next->timer_delta;
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
            if (max_fd < c->fd)
                max_fd = c->fd;
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
        delta = ngx_msec() - delta;

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
            ngx_del_timer(ev);

            if (ev->write)
                ngx_select_del_event(ev, NGX_WRITE_EVENT, 0);
            else
                ngx_select_del_event(ev, NGX_READ_EVENT, 0);
        }

        if (ev->event_handler(ev) == NGX_ERROR)
            ev->close_handler(ev);
    }

    if (ready != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "select ready != events");
    }

    if (timer && timer_queue.timer_next != &timer_queue) {
        if (delta >= timer_queue.timer_next->timer_delta) {
            for ( ;; ) {
                ev = timer_queue.timer_next;

                if (ev == &timer_queue || delta < ev->timer_delta) {
                    break;
                }

                delta -= ev->timer_delta;

                ngx_del_timer(ev);
                ev->timedout = 1;
                if (ev->event_handler(ev) == NGX_ERROR) {
                    ev->close_handler(ev);
                }
            }

        } else {
           timer_queue.timer_next->timer_delta -= delta;
        }
    }

    return NGX_OK;
}

void ngx_select_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t *e;

#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
    ngx_log_debug(ev->log, "set timer: %d:%d" _ c->fd _ timer);
#endif

    if (ev->timer_next || ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already set");
        return;
    }

    for (e = timer_queue.timer_next;
         e != &timer_queue && timer > e->timer_delta;
         e = e->timer_next)
    {
        timer -= e->timer_delta;
    }

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}
