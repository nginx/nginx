
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/* the buffer size is enough to hold "struct sockaddr_un" */
#define NGX_SOCKLEN  512


static void ngx_close_accepted_connection(ngx_connection_t *c);


void
ngx_event_accept(ngx_event_t *ev)
{
    socklen_t          sl;
    ngx_err_t          err;
    ngx_log_t         *log;
    ngx_uint_t         instance;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_listening_t   *ls;
    ngx_connection_t  *c, *lc;
    ngx_event_conf_t  *ecf;
    char               sa[NGX_SOCKLEN];

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        ev->available = 1;

    } else if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        sl = NGX_SOCKLEN;

        s = accept(lc->fd, (struct sockaddr *) sa, &sl);

        if (s == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error((err == NGX_ECONNABORTED) ? NGX_LOG_CRIT:
                                                      NGX_LOG_ALERT,
                          ev->log, err, "accept() failed");

            if (err == NGX_ECONNABORTED) {
                if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    continue;
                }
            }

            return;
        }

#if (NGX_STAT_STUB)
        ngx_atomic_inc(ngx_stat_accepted);
        ngx_atomic_inc(ngx_stat_active);
#endif

        ngx_accept_disabled = NGX_ACCEPT_THRESHOLD
                              - ngx_cycle->free_connection_n;

        c = ngx_get_connection(s, ev->log);

        if (c == NULL) {
            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return;
        }

        rev = c->read;
        wev = c->write;

        ngx_memzero(c, sizeof(ngx_connection_t));

        c->read = rev;
        c->write = wev;
        c->fd = s;
        c->log = ev->log;

        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        c->sockaddr = ngx_palloc(c->pool, sl);
        if (c->sockaddr == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        ngx_memcpy(c->sockaddr, sa, sl);

        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        /* set a blocking mode for aio and non-blocking mode for others */

        if (ngx_inherited_nonblocking) {
            if (ngx_event_flags & NGX_USE_AIO_EVENT) {
                if (ngx_blocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_blocking_n " failed");
                    ngx_close_accepted_connection(c);
                    return;
                }
            }

        } else {
            if (!(ngx_event_flags & (NGX_USE_AIO_EVENT|NGX_USE_RTSIG_EVENT))) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_nonblocking_n " failed");
                    ngx_close_accepted_connection(c);
                    return;
                }
            }
        }

        *log = ls->log;

        c->recv = ngx_recv;
        c->send = ngx_send;
        c->send_chain = ngx_send_chain;

        c->log = log;
        c->pool->log = log;

        c->listening = ls;
        c->socklen = sl;

        c->unexpected_eof = 1;

        c->ctx = lc->ctx;
        c->servers = lc->servers;

        instance = rev->instance;

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));

        rev->instance = !instance;
        wev->instance = !instance;

        rev->index = NGX_INVALID_INDEX;
        wev->index = NGX_INVALID_INDEX;

        rev->data = c;
        wev->data = c;

        wev->write = 1;
        wev->ready = 1;

        if (ngx_event_flags & (NGX_USE_AIO_EVENT|NGX_USE_RTSIG_EVENT)) {
            /* rtsig, aio, iocp */
            rev->ready = 1;
        }

        if (ev->deferred_accept) {
            rev->ready = 1;
#if (NGX_HAVE_KQUEUE)
            rev->available = 1;
#endif
        }

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - atomic increment (x86: lock xadd)
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - atomic increment (x86: lock xadd)
         *             or protection by critical section or light mutex
         */

        c->number = ngx_atomic_inc(ngx_connection_counter);

#if (NGX_STAT_STUB)
        ngx_atomic_inc(ngx_stat_handled);
#endif

#if (NGX_THREADS)
        rev->lock = &c->lock;
        wev->lock = &c->lock;
        rev->own_lock = &c->lock;
        wev->own_lock = &c->lock;
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "accept: fd:%d c:%d", s, c->number);

        if (ls->addr_ntop) {
            c->addr_text.data = ngx_palloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_close_accepted_connection(c);
                return;
            }
    
            c->addr_text.len = ngx_sock_ntop(ls->family, c->sockaddr,
                                             c->addr_text.data,
                                             ls->addr_text_max_len);
            if (c->addr_text.len == 0) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {

        uint32_t            *addr;
        in_addr_t            i;
        struct sockaddr_in  *sin;

        sin = (struct sockaddr_in *) sa;
        addr = ecf->debug_connection.elts;
        for (i = 0; i < ecf->debug_connection.nelts; i++) {
            if (addr[i] == sin->sin_addr.s_addr) {
                log->log_level = NGX_LOG_DEBUG_CONNECTION|NGX_LOG_DEBUG_ALL;
                break;
            }
        }

        }
#endif

        if (ngx_add_conn && (ngx_event_flags & NGX_USE_EPOLL_EVENT) == 0) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available--;
        }

    } while (ev->available);
}


ngx_int_t
ngx_trylock_accept_mutex(ngx_cycle_t *cycle)
{
    if (*ngx_accept_mutex == 0
        && ngx_atomic_cmp_set(ngx_accept_mutex, 0, ngx_pid))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        if (!ngx_accept_mutex_held) {
            if (ngx_enable_accept_events(cycle) == NGX_ERROR) {
                *ngx_accept_mutex = 0;
                return NGX_ERROR;
            }

            ngx_accept_mutex_held = 1;
        }

        return NGX_OK;
    }

    if (ngx_accept_mutex_held) {
        if (ngx_disable_accept_events(cycle) == NGX_ERROR) {
            return NGX_ERROR;
        }

        ngx_accept_mutex_held = 0;
    }

    return NGX_OK;
}


ngx_int_t
ngx_enable_accept_events(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            if (ngx_add_event(c->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_disable_accept_events(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (!c->read->active) {
            continue;
        }

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            if (ngx_del_conn(c, NGX_DISABLE_EVENT) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static void
ngx_close_accepted_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    ngx_free_connection(c);

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    if (ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    ngx_atomic_dec(ngx_stat_active);
#endif
}


u_char *
ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    return ngx_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}
