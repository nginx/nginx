
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_time.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_select_module.h>

static fd_set       master_read_fd_set;
static fd_set       master_write_fd_set;
static fd_set       work_read_fd_set;
static fd_set       work_write_fd_set;

#if (WIN32)
static int          max_read;
static int          max_write;
#else
static int          max_fd;
#endif

static ngx_event_t  event_queue;
static ngx_event_t  timer_queue;


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

    FD_ZERO(&master_read_fd_set);
    FD_ZERO(&master_write_fd_set);

    event_queue.prev = &event_queue;
    event_queue.next = &event_queue;

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
}

int ngx_select_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t *c;

    c = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "select fd:%d event:%d" _ c->fd _ event);

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

    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1: 0;

    ev->prev = &event_queue;
    ev->next = event_queue.next;
    event_queue.next->prev = ev;
    event_queue.next = ev;

    return NGX_OK;
}

int ngx_select_del_event(ngx_event_t *ev, int event)
{
    ngx_connection_t *c;
    c = (ngx_connection_t *) ev->data;

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

    if (ev->prev)
        ev->prev->next = ev->next;

    if (ev->next) {
        ev->next->prev = ev->prev;
        ev->prev = NULL;
    }

    if (ev->prev)
        ev->next = NULL;

    return NGX_OK;
}

int ngx_select_process_events(ngx_log_t *log)
{
    int                ready, found;
    u_int              timer, delta;
    ngx_event_t       *ev, *nx;
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
        for (ev = event_queue.next; ev != &event_queue; ev = ev->next) {
            c = (ngx_connection_t *) ev->data;
            if (max_fd < c->fd)
                max_fd = c->fd;
        }

        ngx_log_debug(log, "change max_fd: %d" _ max_fd);
    }
#endif

    ngx_log_debug(log, "select timer: %d" _ timer);

#if (WIN32)
    if ((ready = select(0, &work_read_fd_set, &work_write_fd_set, NULL, tp))
#else
    if ((ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set,
                        NULL, tp))
#endif
               == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, "select() failed");
        return NGX_ERROR;
    }

    ngx_log_debug(log, "select ready %d" _ ready);

    if (timer) {
        delta = ngx_msec() - delta;

    } else {
        ngx_assert((ready != 0), return NGX_ERROR, log,
                   "select() returns no events without timeout");
    }

    ngx_log_debug(log, "select timer: %d, delta: %d" _ timer _ delta);

    if (timer) {
        if (delta >= timer) {
            for (ev = timer_queue.timer_next;
                 ev != &timer_queue && delta >= ev->timer_delta;
                 /* void */)
            {
                delta -= ev->timer_delta;
                nx = ev->timer_next;
                ngx_del_timer(ev);
                ev->timedout = 1;
                if (ev->event_handler(ev) == -1)
                    ev->close_handler(ev);
                ev = nx;
            }

        } else {
           timer_queue.timer_next->timer_delta -= delta;
        }
    }

    for (ev = event_queue.next; ev != &event_queue; /* void */) {
        c = (ngx_connection_t *) ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                ngx_log_debug(log, "select write %d" _
                              c->fd);
                found = 1;
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                ngx_log_debug(log, "select read %d" _
                              c->fd);
                found = 1;
            }
        }

        nx = ev->next;

        if (found) {
            ev->ready = 1;

            if (ev->oneshot) {
                ngx_del_timer(ev);
                if (ev->write)
                    ngx_select_del_event(ev, NGX_WRITE_EVENT);
                else
                    ngx_select_del_event(ev, NGX_READ_EVENT);
            }

            if (ev->event_handler(ev) == -1)
                ev->close_handler(ev);

            ready--;
        }

        ev = nx;
    }

    ngx_assert((ready == 0), /* void */ ; , log, "select ready != events");

    return NGX_OK;
}

void ngx_select_add_timer(ngx_event_t *ev, ngx_msec_t timer)
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
