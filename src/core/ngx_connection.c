
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_os_io_t  ngx_io;


ngx_listening_t *ngx_listening_inet_stream_socket(ngx_conf_t *cf,
                                                 in_addr_t addr,
                                                 in_port_t port)
{
    size_t               len;
    ngx_listening_t     *ls;
    struct sockaddr_in  *addr_in;

    if (!(ls = ngx_array_push(&cf->cycle->listening))) {
        return NULL;
    }

    ngx_memzero(ls, sizeof(ngx_listening_t));

    if (!(addr_in = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in)))) {
        return NULL;
    }

#if (HAVE_SIN_LEN)
    addr_in->sin_len = sizeof(struct sockaddr_in);
#endif
    addr_in->sin_family = AF_INET;
    addr_in->sin_addr.s_addr = addr;
    addr_in->sin_port = htons(port);

    if (!(ls->addr_text.data = ngx_palloc(cf->pool, INET_ADDRSTRLEN + 6))) {
        return NULL;
    }

    len = ngx_inet_ntop(AF_INET, &addr, ls->addr_text.data, INET_ADDRSTRLEN);
    ls->addr_text.len = ngx_snprintf((char *) ls->addr_text.data + len,
                                     6, ":%d", port);

    ls->fd = (ngx_socket_t) -1;
    ls->family = AF_INET;
    ls->type = SOCK_STREAM;
    ls->protocol = IPPROTO_IP;
#if (WIN32)
    ls->flags = WSA_FLAG_OVERLAPPED;
#endif
    ls->sockaddr = (struct sockaddr *) addr_in;
    ls->socklen = sizeof(struct sockaddr_in);
    ls->addr = offsetof(struct sockaddr_in, sin_addr);
    ls->addr_text_max_len = INET_ADDRSTRLEN;

    return ls;
}


ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle)
{
    ngx_uint_t           i;
    ngx_listening_t     *ls;
    struct sockaddr_in  *addr_in;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        /* AF_INET only */

        ls[i].sockaddr = ngx_palloc(cycle->pool, sizeof(struct sockaddr_in));
        if (ls[i].sockaddr == NULL) {
            return NGX_ERROR;
        }

        ls[i].socklen = sizeof(struct sockaddr_in);
        if (getsockname(ls[i].fd, ls[i].sockaddr, &ls[i].socklen) == -1) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                          "getsockname() of the inherited "
                          "socket #%d failed", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        addr_in = (struct sockaddr_in *) ls[i].sockaddr;

        if (addr_in->sin_family != AF_INET) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                          "the inherited socket #%d has "
                          "unsupported family", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }
        ls[i].addr_text_max_len = INET_ADDRSTRLEN;

        ls[i].addr_text.data = ngx_palloc(cycle->pool, ls[i].addr_text_max_len);
        if (ls[i].addr_text.data == NULL) {
            return NGX_ERROR;
        }

        ls[i].family = addr_in->sin_family;
        ls[i].addr_text.len = ngx_sock_ntop(ls[i].family, ls[i].sockaddr,
                                            ls[i].addr_text.data,
                                            ls[i].addr_text_max_len);
        if (ls[i].addr_text.len == 0) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle)
{
    ngx_uint_t        tries, failed, reuseaddr, i;
    ngx_err_t         err;
    ngx_log_t        *log;
    ngx_socket_t      s;
    ngx_listening_t  *ls;

    reuseaddr = 1;
#if (NGX_SUPPRESS_WARN)
    failed = 0;
#endif

    log = cycle->log;

    /* TODO: tries configurable */

    for (tries = /* STUB */ 5; tries; tries--) {
        failed = 0;

        /* for each listening socket */

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (ls[i].ignore) {
                continue;
            }

            if (ls[i].fd != -1) {
                continue;
            }

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                continue;
            }

            s = ngx_socket(ls[i].family, ls[i].type, ls[i].protocol,
                           ls[i].flags);

            if (s == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_socket_n " %s failed", ls[i].addr_text.data);
                return NGX_ERROR;
            }

#if (WIN32)
            /*
             * Winsock assignes a socket number divisible by 4
             * so to find a connection we divide a socket number by 4.
             */

            if (s % 4) {
                ngx_log_error(NGX_LOG_EMERG, ls->log, 0,
                              ngx_socket_n " created socket %d", s);
                return NGX_ERROR;
            }
#endif

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int)) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "setsockopt(SO_REUSEADDR) %s failed",
                              ls[i].addr_text.data);
                return NGX_ERROR;
            }

            /* TODO: close on exit */

            if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    return NGX_ERROR;
                }
            }

#if 0
            if (ls[i].nonblocking) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    return NGX_ERROR;
                }
            }
#endif

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = ngx_socket_errno;
                ngx_log_error(NGX_LOG_EMERG, log, err,
                              "bind() to %s failed", ls[i].addr_text.data);

                if (err != NGX_EADDRINUSE)
                    return NGX_ERROR;

                if (ngx_close_socket(s) == -1)
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_close_socket_n " %s failed",
                                  ls[i].addr_text.data);

                failed = 1;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "listen() to %s failed", ls[i].addr_text.data);
                return NGX_ERROR;
            }

            /* TODO: deferred accept */

            ls[i].fd = s;
        }

        if (!failed)
            break;

        /* TODO: delay configurable */

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");
        ngx_msleep(500);
    }

    if (failed) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "still can not bind()");
        return NGX_ERROR;
    }

    return NGX_OK;
}


void ngx_close_listening_sockets(ngx_cycle_t *cycle)
{
    ngx_uint_t        i;
    ngx_socket_t      fd;
    ngx_listening_t  *ls;

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        return;
    }

    ngx_accept_mutex_held = 0;
    ngx_accept_mutex = NULL;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        fd = ls[i].fd;

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        fd /= 4;
#endif

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            if (cycle->connections[fd].read->active) {
                ngx_del_conn(&cycle->connections[fd], NGX_CLOSE_EVENT);
            }

        } else {
            if (cycle->read_events[fd].active) {
                ngx_del_event(&cycle->read_events[fd],
                              NGX_READ_EVENT, NGX_CLOSE_EVENT);
            }
        }

        if (ngx_close_socket(ls[i].fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                          ngx_close_socket_n " %s failed",
                          ls[i].addr_text.data);
        }

        cycle->connections[fd].fd = (ngx_socket_t) -1;
    }
}


void ngx_close_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }
    
#if (NGX_OPENSSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->read->event_handler = ngx_ssl_close_handler;
            c->write->event_handler = ngx_ssl_close_handler;
            return;
        }
    }
    
#endif

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    
    if (ngx_del_conn) {
        ngx_del_conn(c, NGX_CLOSE_EVENT);

    } else {
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active || c->write->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

#if (NGX_THREADS)

    /*
     * we have to clean the connection information before the closing
     * because another thread may reopen the same file descriptor
     * before we clean the connection
     */

    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_OK) {

        if (c->read->prev) {
            ngx_delete_posted_event(c->read);
        }

        if (c->write->prev) {
            ngx_delete_posted_event(c->write);
        }

        c->read->closed = 1;
        c->write->closed = 1;

        if (c->single_connection) {
            ngx_unlock(&c->lock);
            c->read->locked = 0;
            c->write->locked = 0;
        }

        ngx_mutex_unlock(ngx_posted_events_mutex);
    }

#else

    if (c->read->prev) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->prev) {
        ngx_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

#endif

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;
    c->data = NULL;

    ngx_destroy_pool(c->pool);

    if (ngx_close_socket(fd) == -1) {

        /* we use ngx_cycle->log because c->log was in c->pool */

        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }
}



ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text)
{
    ngx_uint_t  level;

    if (err == NGX_ECONNRESET
        && c->log_error == NGX_ERROR_IGNORE_ECONNRESET)
    {
        return 0;
    }

    if (err == NGX_ECONNRESET
#if !(WIN32)
        || err == NGX_EPIPE
#endif
        || err == NGX_ENOTCONN
        || err == NGX_ECONNREFUSED
        || err == NGX_EHOSTUNREACH)
    {

        switch (c->log_error) {

        case NGX_ERROR_IGNORE_ECONNRESET:
        case NGX_ERROR_INFO:
            level = NGX_LOG_INFO;
            break;

        case NGX_ERROR_ERR:
            level = NGX_LOG_ERR;
            break;

        default:
            level = NGX_LOG_CRIT;
        }

    } else {
        level = NGX_LOG_CRIT;
    }

    ngx_log_error(level, c->log, err, text);

    return NGX_ERROR;
}
