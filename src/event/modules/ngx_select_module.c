
#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_time.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_select_module.h>

static fd_set       master_read_fds;
static fd_set       master_write_fds;
static fd_set       work_read_fds;
static fd_set       work_write_fds;

#if (WIN32)
static int          max_read;
static int          max_write;
#else
static int          max_fd;
#endif

static ngx_event_t  event_queue;
static ngx_event_t  timer_queue;


static void ngx_add_timer_core(ngx_event_t *ev, u_int timer);
static void ngx_inline ngx_del_timer(ngx_event_t *ev);

static fd_set *ngx_select_get_fd_set(ngx_socket_t fd, int event,
                                     ngx_log_t *log);

void ngx_select_init(int max_connections, ngx_log_t *log)
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

    FD_ZERO(&master_read_fds);
    FD_ZERO(&master_write_fds);

    event_queue.prev = &event_queue;
    event_queue.next = &event_queue;

    timer_queue.timer_prev = &timer_queue;
    timer_queue.timer_next = &timer_queue;

    ngx_event_actions.add = ngx_select_add_event;
    ngx_event_actions.del = ngx_select_del_event;
    ngx_event_actions.process = ngx_select_process_events;

#if (WIN32)
    max_read = max_write = 0;
#else
    max_fd = -1;
#endif
}

int ngx_select_add_event(ngx_event_t *ev, int event, u_int flags)
{
    fd_set *fds;
    ngx_connection_t *cn = (ngx_connection_t *) ev->data;

    if (event == NGX_TIMER_EVENT) {
        ngx_add_timer_core(ev, flags);
        return 0;
    }

    ngx_assert((flags != NGX_ONESHOT_EVENT), return -1, ev->log,
               "ngx_select_add_event: NGX_ONESHOT_EVENT is not supported");

    fds = ngx_select_get_fd_set(cn->fd, event, ev->log);
    if (fds == NULL)
        return -1;

    ev->prev = &event_queue;
    ev->next = event_queue.next;
    event_queue.next->prev = ev;
    event_queue.next = ev;

    FD_SET(cn->fd, fds);

#if (WIN32)
    switch (event) {
    case NGX_READ_EVENT:
        max_read++;
        break;
    case NGX_WRITE_EVENT:
        max_write++;
        break;
    }
#else
    if (max_fd != -1 && max_fd < cn->fd)
        max_fd = cn->fd;
#endif

    return 0;
}

int ngx_select_del_event(ngx_event_t *ev, int event)
{
    fd_set *fds;
    ngx_connection_t *cn = (ngx_connection_t *) ev->data;

    if (event == NGX_TIMER_EVENT) {
        ngx_del_timer(ev);
        return 0;
    }

    fds = ngx_select_get_fd_set(cn->fd, event, ev->log);
    if (fds == NULL)
        return -1;

    if (ev->prev)
        ev->prev->next = ev->next;

    if (ev->next) {
        ev->next->prev = ev->prev;
        ev->prev = NULL;
    }

    if (ev->prev)
        ev->next = NULL;

    FD_CLR(cn->fd, fds);

#if (WIN32)
    switch (event) {
    case NGX_READ_EVENT:
        max_read--;
        break;
    case NGX_WRITE_EVENT:
        max_write--;
        break;
    }
#else
    if (max_fd == cn->fd)
        max_fd = -1;
#endif

    return 0;
}

static fd_set *ngx_select_get_fd_set(ngx_socket_t fd, int event, ngx_log_t *log)
{
    ngx_log_debug(log, "ngx_select_get_fd_set: %d %d" _ fd _ event);

#if !(WIN32)
    if (fd >= FD_SETSIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ngx_select_get_event: maximum descriptor number"
                      "supported by select() is %d",
                      FD_SETSIZE - 1);
        return NULL;
    }
#endif

    switch (event) {
    case NGX_READ_EVENT:
#if (WIN32)
        if (max_read >= FD_SETSIZE) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ngx_select_get_event: maximum number of descriptors "
                          "supported by select() is %d",
                          FD_SETSIZE);
            return NULL;
        }
#endif
        return &master_read_fds;

    case NGX_WRITE_EVENT:
#if (WIN32)
        if (max_write >= FD_SETSIZE) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ngx_select_get_event: maximum number of descriptors "
                          "supported by select() is %d",
                          FD_SETSIZE);
            return NULL;
        }
#endif
        return &master_write_fds;

    default:
        ngx_assert(0, return NULL, log,
                      "ngx_select_get_fd_set: invalid event %d" _ event);
    }

    return NULL;
}

int ngx_select_process_events(ngx_log_t *log)
{
    int                ready, found;
    u_int              timer, delta;
    ngx_event_t       *ev, *nx;
    ngx_connection_t  *cn;
    struct timeval     tv, *tp;

    work_read_fds = master_read_fds;
    work_write_fds = master_write_fds;

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
        for (ev = event_queue.next; ev != &event_queue; ev = ev->next) {
            cn = (ngx_connection_t *) ev->data;
            if (max_fd < cn->fd)
                max_fd = cn->fd;
        }

        ngx_log_debug(log, "ngx_select_process_events: change max_fd: %d" _
                      max_fd);
    }
#endif

    ngx_log_debug(log, "ngx_select_process_events: timer: %d" _ timer);

#if (WIN32)
    if ((ready = select(0, &work_read_fds, &work_write_fds, NULL, tp))
#else
    if ((ready = select(max_fd + 1, &work_read_fds, &work_write_fds, NULL, tp))
#endif
               == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                     "ngx_select_process_events: select failed");
        return -1;
    }

    ngx_log_debug(log, "ngx_select_process_events: ready %d" _ ready);

    if (timer) {
        delta = ngx_msec() - delta;

    } else {
        ngx_assert((ready != 0), return -1, log,
                   "ngx_select_process_events: "
                   "select returns no events without timeout");
    }

    ngx_log_debug(log, "ngx_select_process_events: "
                       "timer: %d, delta: %d" _ timer _ delta);

    if (timer) {
        if (delta >= timer) {
            for (ev = timer_queue.timer_next;
                 ev != &timer_queue && delta >= ev->timer_delta;
                 /* void */)
            {
                delta -= ev->timer_delta;
                nx = ev->timer_next;
                ngx_del_timer(ev);
#if 1
                ev->timedout = 1;
                if (ev->event_handler(ev) == -1)
                    ev->close_handler(ev);
#else
                if (ev->timer_handler(ev) == -1)
                    ev->close_handler(ev);
#endif
                ev = nx;
            }

        } else {
           timer_queue.timer_next->timer_delta -= delta;
        }
    }

    for (ev = event_queue.next; ev != &event_queue; ev = ev->next) {
        cn = (ngx_connection_t *) ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(cn->fd, &work_write_fds)) {
                ngx_log_debug(log, "ngx_select_process_events: write %d" _
                              cn->fd);
                found = 1;
            }

        } else {
            if (FD_ISSET(cn->fd, &work_read_fds)) {
                ngx_log_debug(log, "ngx_select_process_events: read %d" _
                              cn->fd);
                found = 1;
            }
        }

        if (found) {
            ev->ready = 1;
            if (ev->event_handler(ev) == -1)
                ev->close_handler(ev);

            ready--;
        }

    }

    ngx_assert((ready == 0), return 0, log,
               "ngx_select_process_events: ready != events");

    return 0;
}

static void ngx_add_timer_core(ngx_event_t *ev, u_int timer)
{
    ngx_event_t *e;

    for (e = timer_queue.timer_next;
         e != &timer_queue && timer > e->timer_delta;
         e = e->timer_next)
        timer -= e->timer_delta;

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}

static void ngx_inline ngx_del_timer(ngx_event_t *ev)
{
    if (ev->timer_prev)
        ev->timer_prev->timer_next = ev->timer_next;

    if (ev->timer_next) {
        ev->timer_next->timer_prev = ev->timer_prev;
        ev->timer_prev = NULL;
    }

    if (ev->timer_prev)
        ev->timer_next = NULL;
}
