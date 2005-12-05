
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_connection_t      *connection;

    struct sockaddr       *sockaddr;
    socklen_t              socklen;

    ngx_str_r              server;
    ngx_str_r              name;

    ngx_event_handler_pt   handler;

    ngx_log_t             *pool;
    ngx_log_t             *log;
} ngx_resolver_t;


ngx_int_t
ngx_gethostbyname(ngx_resolver_t *r)
{
    ngx_socket_t  s;

    if (r->connection) {
        return NGX_OK;
    }

    s = ngx_socket(AF_INET, SOCK_DGRAM, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, r->log, 0, "socket %d", s);

    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    c = ngx_get_connection(s, r->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, r->log, ngx_socket_errno,
                          ngx_close_socket_n "failed");
        }

        return NGX_ERROR;
    }

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    r->connection = c;

    /*
     * TODO: MT: - ngx_atomic_fetch_add()
     *             or protection by critical section or mutex
     *
     * TODO: MP: - allocated in a shared memory
     *           - ngx_atomic_fetch_add()
     *             or protection by critical section or mutex
     */

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_THREADS)
    rev->lock = pc->lock;
    wev->lock = pc->lock;
    rev->own_lock = &c->lock;
    wev->own_lock = &c->lock;
#endif

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%d", &r->server, s, c->number);

    rc = connect(s, r->sockaddr, r->socklen);

    if (rc == -1) {
        ngx_log_error(level, r->log, ngx_socket_errno,
                      "connect() to %V failed", &r->server);

        return NGX_ERROR;
    }







    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }


    if (ngx_add_conn) {
        if (rc == -1) {

            /* NGX_EINPROGRESS */

            return NGX_AGAIN;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");

        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_AIO_EVENT) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, ngx_socket_errno,
                       "connect(): %d", rc);

        /* aio, iocp */

        if (ngx_blocking(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_blocking_n " failed");
            return NGX_ERROR;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NGX_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NGX_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        return NGX_ERROR;
    }

    if (rc == -1) {

        /* NGX_EINPROGRESS */

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");

    wev->ready = 1;

    return NGX_OK;
}
