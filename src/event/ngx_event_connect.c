
#include <ngx_event_connect.h>


int ngx_event_connect_peer(ngx_peer_connecttion_t *pc)
{
    time_t        now;
    ngx_socket_t  s;

    /* ngx_lock_mutex(pc->peers->mutex); */

    if (pc->peers->last_cached) {

        /* cached connection */

        pc->connection = pc->peers->cached[pc->peers->last_cached]
        pc->peers->last_cached--;

        /* ngx_unlock_mutex(pc->peers->mutex); */

        pc->cached = 1;
        return NGX_OK;
    }

    /* ngx_unlock_mutex(pc->peers->mutex); */

    pc->cached = 0;

    now = ngx_time();

    if (pc->peers->number > 1) {

        /* there are several peers */

        if (pc->tries == pc->peers->number) {

            /* it's a first try - get a current peer */

            /* Here is the race condition when the peers are shared between
               the threads or the processes but it should not be serious */

            pc->cur_peer = pc->peers->current++;

            if (cp->peers->current >= cp->peers->number) {
                pc->peers->current = 0;
            }

            /* the end of the race condition */

#if (NGX_MULTITHREADED || NGX_MULTIPROCESSED)
            /* eliminate the sequences of the race condition */

            if (pc->cur_peer >= pc->peers->number) {
                pc->cur_peer = 0;
            }
#endif
        }

        if (pc->peers->max_fails > 0) {

            /* the peers support a fault tolerance */

            for ( ;; ) {
                peer = &pc->peers->peers[pc->cur_peer];

                /* Here is the race condition when the peers are shared between
                   the threads or the processes but it should not be serious */

                if (peer->fails <= pc->peers->max_fails
                    || (now - peer->accessed > pc->peers->fail_timeout))
                {
                    break;
                }

                /* the end of the race condition */

                pc->cur_peer++;

                if (pc->cur_peer >= pc->peers->number) {
                    pc->cur_peer = 0;
                }

                pc->tries--;

                if (pc->tries == 0) {
                    return NGX_ERROR;
                }
            }
        }
    }

    pc->addr_port_text = peer->addr_port_text;

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

    rev->index = wev->index = NGX_INVALID_INDEX;
    rev->data = wev->data = c;
    c->read = rev;
    c->write = wev;

    rev->instance = wev->instance = !instance;

    rev->log = wev->log = c->log = pc->log;
    c->fd = s;

    pc->connection = c;

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            return NGX_ERROR;
        }
    } 

}
