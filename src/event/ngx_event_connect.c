
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


/* AF_INET only */

int ngx_event_connect_peer(ngx_peer_connection_t *pc)
{
    int                  rc, instance;
    u_int                event;
    time_t               now;
    ngx_err_t            err;
    ngx_peer_t          *peer;
    ngx_socket_t         s;
    ngx_event_t         *rev, *wev;
    ngx_connection_t    *c;
    struct sockaddr_in   addr;

    now = ngx_time();

    /* ngx_lock_mutex(pc->peers->mutex); */

    if (pc->peers->last_cached) {

        /* cached connection */

        pc->connection = pc->peers->cached[pc->peers->last_cached];
        pc->peers->last_cached--;

        /* ngx_unlock_mutex(pc->peers->mutex); */

        pc->cached = 1;
        return NGX_OK;
    }

    pc->cached = 0;
    pc->connection = NULL;

    if (pc->peers->number == 1) {
        peer = &pc->peers->peers[0];

    } else {

        /* there are several peers */

        if (pc->tries == pc->peers->number) {

            /* it's a first try - get a current peer */

            pc->cur_peer = pc->peers->current++;

            if (pc->peers->current >= pc->peers->number) {
                pc->peers->current = 0;
            }
        }

        if (pc->peers->max_fails == 0) {
            peer = &pc->peers->peers[pc->cur_peer];

        } else {

            /* the peers support a fault tolerance */

            for ( ;; ) {
                peer = &pc->peers->peers[pc->cur_peer];

                if (peer->fails <= pc->peers->max_fails
                    || (now - peer->accessed > pc->peers->fail_timeout))
                {
                    break;
                }

                pc->cur_peer++;

                if (pc->cur_peer >= pc->peers->number) {
                    pc->cur_peer = 0;
                }

                pc->tries--;

                if (pc->tries == 0) {
                    /* ngx_unlock_mutex(pc->peers->mutex); */

                    return NGX_ERROR;
                }
            }
        }
    }

    /* ngx_unlock_mutex(pc->peers->mutex); */


    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, 0);

    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");

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

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }

#if (WIN32)
    /*
     * Winsock assignes a socket number divisible by 4
     * so to find a connection we divide a socket number by 4.
     */

    if (s % 4) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      ngx_socket_n
                      " created socket %d, not divisible by 4", s);
        exit(1);
    }

    c = &ngx_cycle->connections[s / 4];
    rev = &ngx_cycle->read_events[s / 4];
    wev = &ngx_cycle->write_events[s / 4];

#else

    c = &ngx_cycle->connections[s];
    rev = &ngx_cycle->read_events[s];
    wev = &ngx_cycle->write_events[s];

#endif

    instance = rev->instance;

    ngx_memzero(c, sizeof(ngx_connection_t));
    ngx_memzero(rev, sizeof(ngx_event_t));
    ngx_memzero(wev, sizeof(ngx_event_t));

    rev->index = NGX_INVALID_INDEX;
    wev->index = NGX_INVALID_INDEX;

    rev->data = c;
    wev->data = c;

    c->read = rev;
    c->write = wev;
    wev->write = 1;

    rev->instance = !instance;
    wev->instance = !instance;

    c->log = pc->log;
    rev->log = pc->log;
    wev->log = pc->log;

    c->fd = s;

    pc->connection = c;

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            return NGX_ERROR;
        }
    } 

    ngx_memzero(&addr, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_port = peer->port;
    addr.sin_addr.s_addr = peer->addr;

ngx_log_debug(pc->log, "CONNECT: %s" _ peer->addr_port_text.data);

    rc = connect(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

    if (rc == -1) {
        err = ngx_socket_errno;

        /* Winsock returns WSAEWOULDBLOCK */

        if (err != NGX_EINPROGRESS && err != NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_ERR, pc->log, err, "connect() failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            c->fd = -1;

            return NGX_CONNECT_ERROR;
        }
    }

    if (ngx_event_flags & NGX_USE_AIO_EVENT) {

        /* aio, iocp */

        if (ngx_blocking(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_blocking_n " failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_ERROR;
        }

        /*
         * aio allows to post operation on non-connected socket
         * at least in FreeBSD.
         * NT does not support it.
         * 
         * TODO: check in Win32, etc. As workaround we can use NGX_ONESHOT_EVENT
         */
 
        rev->ready = 1;
        wev->ready = 1;

        return NGX_OK;
    }

    /* TODO: epoll */

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {     /* kqueue */
        event = NGX_CLEAR_EVENT;

    } else {                                  /* select, poll, /dev/poll */
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

ngx_log_debug(pc->log, "CONNECTED");

    wev->ready = 1;

    return NGX_OK;
}


void ngx_event_connect_peer_failed(ngx_peer_connection_t *pc)
{
    time_t  now;

    now = ngx_time();

    /* ngx_lock_mutex(pc->peers->mutex); */

    pc->peers->peers[pc->cur_peer].fails++;
    pc->peers->peers[pc->cur_peer].accessed = now;

    /* ngx_unlock_mutex(pc->peers->mutex); */

    pc->cur_peer++;

    if (pc->cur_peer >= pc->peers->number) {
        pc->cur_peer = 0;
    }

    pc->tries--;

    return;
}
