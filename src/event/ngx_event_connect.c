
#include <ngx_event_connect.h>


int ngx_event_connect_peer(ngx_connect_peer_t *cp)
{
    time_t   now;

    /* TODO: cached connection */

    now = ngx_time();

    if (cp->peers->number > 1) {

        /* there are several peers */

        if (cp->tries == cp->peers->number) {

            /* it's a first try - get a current peer */

            /* Here is the race condition when the peers are shared between
               the threads or the processes but it should not be serious */

            cp->cur_peer = cp->peers->current++;

            if (cp->peers->current >= cp->peers->number) {
                cp->peers->current = 0;
            }

            /* the end of the race condition */

#if (NGX_MULTITHREADED || NGX_MULTIPROCESSED)
            /* eliminate the sequences of the race condition */

            if (cp->cur_peer >= cp->peers->number) {
                cp->cur_peer = 0;
            }
#endif
        }

        if (cp->peers->max_fails > 0) {

            /* the peers support a fault tolerance */

            for ( ;; ) {
                peer = &cp->peers->peers[cp->cur_peer];

                /* Here is the race condition when the peers are shared between
                   the threads or the processes but it should not be serious */

                if (peer->fails <= cp->peers->max_fails
                    || (now - peer->accessed > cp->peers->fail_timeout))
                {
                    break;
                }

                /* the end of the race condition */

                cp->cur_peer++;

                if (cp->cur_peer >= cp->peers->number) {
                    cp->cur_peer = 0;
                }

                cp->tries--;

                if (cp->tries == 0) {
                    return NGX_ERROR;
                }
            }
        }
    }





    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, 0);

    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, cp->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    if (cp->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &cp->rcvbuf, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cp->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cp->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_ERROR;
        }
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cn->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cn->log, ngx_socket_errno,
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
            ngx_log_error(NGX_LOG_EMERG, cp->log, 0,
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

    !!!!!!!!!!!!!!!

    rev->log = wev->log = c->log = cn->log;
    c->fd = s;
    wev->close_handler = rev->close_handler = ngx_event_close_connection;
}
