
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


static size_t ngx_accept_log_error(void *data, char *buf, size_t len);


void ngx_event_accept(ngx_event_t *ev)
{
    int                    instance, accepted;
    socklen_t              len;
    struct sockaddr       *sa;
    ngx_err_t              err;
    ngx_log_t             *log;
    ngx_pool_t            *pool;
    ngx_socket_t           s;
    ngx_event_t           *rev, *wev;
    ngx_connection_t      *c, *ls;
    ngx_event_conf_t      *ecf;

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    ls = ev->data;

    ngx_log_debug(ev->log, "accept on %s ready: %d" _
                  ls->listening->addr_text.data _
                  ev->available);

    ev->ready = 0;
    accepted = 0;

    do {

        /*
         * Create the pool before accept() to avoid copy the sockaddr.
         * Although accept() can fail it's an uncommon case
         * and besides the pool can be got from the free pool list
         */

        if (!(pool = ngx_create_pool(ls->listening->pool_size, ev->log))) {
            return;
        }

        if (!(sa = ngx_palloc(pool, ls->listening->socklen))) {
            return;
        }

        if (!(log = ngx_palloc(pool, sizeof(ngx_log_t)))) {
            return;
        }
        ngx_memcpy(log, ls->log, sizeof(ngx_log_t));
        pool->log = log;

        log->data = ls->listening->addr_text.data;
        log->handler = ngx_accept_log_error;

        len = ls->listening->socklen;

        s = accept(ls->fd, sa, &len);
        if (s == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_NOTICE, log, err,
                              "EAGAIN after %d accepted connection(s)",
                              accepted);
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "accept() on %s failed",
                          ls->listening->addr_text.data);

            ngx_destroy_pool(pool);
            return;
        }

        /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */

        if ((unsigned) s >= (unsigned) ecf->connections) {

            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "accept() on %s returned socket #%d while "
                          "only %d connections was configured, "
                          "closing the connection",
                          ls->listening->addr_text.data, s, ecf->connections);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              ngx_close_socket_n "failed");
            }

            /* TODO: disable temporary accept() event */

            ngx_destroy_pool(pool);
            return;
        }

        /* set a blocking mode for aio and non-blocking mode for others */

        if (ngx_inherited_nonblocking) {
            if ((ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_blocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                  ngx_blocking_n " failed");

                    if (ngx_close_socket(s) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
                    }

                    ngx_destroy_pool(pool);
                    return;
                }
            }

        } else {
            if ((ngx_event_flags & NGX_USE_AIO_EVENT) == 0) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                  ngx_nonblocking_n " failed");

                    if (ngx_close_socket(s) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
                    }

                    ngx_destroy_pool(pool);
                    return;
                }
            }
        }

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        if (s % 4) {
            ngx_log_error(NGX_LOG_EMERG, ev->log, 0,
                          "accept() on %s returned socket #%d, "
                          "not divisible by 4",
                          ls->listening->addr_text.data, s);
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

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));
        ngx_memzero(c, sizeof(ngx_connection_t));

        c->pool = pool;

        c->listening = ls->listening;
        c->sockaddr = sa;
        c->socklen = len;

        rev->instance = !instance;
        wev->instance = !instance;

        rev->index = NGX_INVALID_INDEX;
        wev->index = NGX_INVALID_INDEX;

        rev->data = c;
        wev->data = c;

        c->read = rev;
        c->write = wev;

        c->fd = s;
        c->unexpected_eof = 1;

        wev->write = 1;
        wev->ready = 1;

        if (ngx_event_flags & (NGX_USE_AIO_EVENT|NGX_USE_EDGE_EVENT)) {
            /* aio, iocp, epoll */
            rev->ready = 1;
        }

        if (ev->deferred_accept) {
            rev->ready = 1;
        }

        c->ctx = ls->ctx;
        c->servers = ls->servers;

        c->log = log;
        rev->log = log;
        wev->log = log;

        /*
         * In the multithreaded model the connection counter is updated by
         * the main thread only that accept()s connections.
         *
         * TODO: MP: - allocated in a shared memory
         *           - atomic increment (x86: lock xadd)
         *             or protection by critical section or mutex
         */

        c->number = ngx_connection_counter++;

        ngx_log_debug(ev->log, "LOG: %x" _ ev->log->log_level);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "accept: %d, %d", s, c->number);

        if (ngx_add_conn) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                if (ngx_close_socket(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_close_socket_n " failed");
                }

                ngx_destroy_pool(pool);
                return;
            }
        }

        log->data = NULL;
        log->handler = NULL;

        ls->listening->handler(c);

        if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
            ev->available--;
        }

        accepted++;

    } while (ev->available);

    return;
}


static size_t ngx_accept_log_error(void *data, char *buf, size_t len)
{
    char *sock = data;

    return ngx_snprintf(buf, len, " while accept() on %s", sock);
}
