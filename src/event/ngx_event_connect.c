
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


ngx_int_t
ngx_event_connect_peer(ngx_peer_connection_t *pc)
{
    int                rc;
    ngx_uint_t         level, i;
    u_int              event;
    time_t             now;
    ngx_err_t          err;
    ngx_peer_t        *peer;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;

    now = ngx_time();

    /* ngx_lock_mutex(pc->peers->mutex); */

    if (pc->peers->last_cached) {

        /* cached connection */

        c = pc->peers->cached[pc->peers->last_cached];
        pc->peers->last_cached--;

        /* ngx_unlock_mutex(pc->peers->mutex); */

#if (NGX_THREADS)
        c->read->lock = c->read->own_lock;
        c->write->lock = c->write->own_lock;
#endif

        pc->connection = c;
        pc->cached = 1;

        return NGX_OK;
    }

    pc->cached = 0;
    pc->connection = NULL;

    if (pc->peers->number == 1) {
        peer = &pc->peers->peer[0];

    } else {

        /* there are several peers */

        if (pc->tries == pc->peers->number) {

            /* it's a first try - get a current peer */

            pc->cur_peer = pc->peers->current;

            pc->peers->weight--;

            if (pc->peers->weight == 0) {
                pc->peers->current++;
            }

            if (pc->peers->current >= pc->peers->number) {
                pc->peers->current = 0;
            }

            if (pc->peers->weight == 0) {
                pc->peers->weight = pc->peers->peer[pc->peers->current].weight;
            }
        }

        for ( ;; ) {
            peer = &pc->peers->peer[pc->cur_peer];

            if (peer->max_fails == 0 || peer->fails <= peer->max_fails) {
                break;
            }

            if (now - peer->accessed > peer->fail_timeout) {
                peer->fails = 0;
                break;
            }

            pc->cur_peer++;

            if (pc->cur_peer >= pc->peers->number) {
                pc->cur_peer = 0;
            }

            pc->tries--;

            if (pc->tries == 0) {

                /* all peers failed, mark them as live for quick recovery */

                for (i = 0; i < pc->peers->number; i++) {
                    pc->peers->peer[i].fails = 0;
                }

                /* ngx_unlock_mutex(pc->peers->mutex); */

                return NGX_BUSY;
            }
        }
    }

    /* ngx_unlock_mutex(pc->peers->mutex); */


    s = ngx_socket(peer->sockaddr->sa_family, SOCK_STREAM, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "socket %d", s);

    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }


    c = ngx_get_connection(s, pc->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_close_socket_n "failed");
        }

        return NGX_ERROR;
    }

    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");

            ngx_free_connection(c);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_ERROR;
        }
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        ngx_free_connection(c);

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

    c->recv = ngx_recv;
    c->send = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;

    c->log_error = pc->log_error;

    if (peer->sockaddr->sa_family != AF_INET) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
        c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

#if (NGX_SOLARIS)
        /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
        c->sendfile = 0;
#endif
    }

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    pc->connection = c;

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

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%d", &peer->name, s, c->number);

    rc = connect(s, peer->sockaddr, peer->socklen);

    if (rc == -1) {
        err = ngx_socket_errno;

        /* Winsock returns WSAEWOULDBLOCK (NGX_EAGAIN) */

        if (err != NGX_EINPROGRESS && err != NGX_EAGAIN) {

            if (err == NGX_ECONNREFUSED || err == NGX_EHOSTUNREACH) {
                level = NGX_LOG_ERR;
            } else {
                level = NGX_LOG_CRIT;
            }

            ngx_log_error(level, c->log, err, "connect() to %V failed",
                          &peer->name);

            return NGX_DECLINED;
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


void
ngx_event_connect_peer_failed(ngx_peer_connection_t *pc, ngx_uint_t down)
{
    time_t  now;

    if (down) {
        now = ngx_time();

        /* ngx_lock_mutex(pc->peers->mutex); */

        pc->peers->peer[pc->cur_peer].fails++;
        pc->peers->peer[pc->cur_peer].accessed = now;

        /* ngx_unlock_mutex(pc->peers->mutex); */
    }

    pc->cur_peer++;

    if (pc->cur_peer >= pc->peers->number) {
        pc->cur_peer = 0;
    }

    if (pc->tries) {
        pc->tries--;
    }
}
