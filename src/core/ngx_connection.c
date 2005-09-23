
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_os_io_t  ngx_io;


ngx_listening_t *
ngx_listening_inet_stream_socket(ngx_conf_t *cf, in_addr_t addr, in_port_t port)
{
    size_t               len;
    ngx_listening_t     *ls;
    struct sockaddr_in  *sin;

    ls = ngx_array_push(&cf->cycle->listening);
    if (ls == NULL) {
        return NULL;
    }

    ngx_memzero(ls, sizeof(ngx_listening_t));

    sin = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
    if (sin == NULL) {
        return NULL;
    }

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;
    sin->sin_port = htons(port);


    ls->addr_text.data = ngx_palloc(cf->pool,
                                    INET_ADDRSTRLEN - 1 + sizeof(":65535") - 1);
    if (ls->addr_text.data == NULL) {
        return NULL;
    }

    len = ngx_inet_ntop(AF_INET, &addr, ls->addr_text.data, INET_ADDRSTRLEN);

    ls->addr_text.len = ngx_sprintf(ls->addr_text.data + len, ":%d", port)
                        - ls->addr_text.data;

    ls->fd = (ngx_socket_t) -1;
    ls->family = AF_INET;
    ls->type = SOCK_STREAM;
    ls->sockaddr = (struct sockaddr *) sin;
    ls->socklen = sizeof(struct sockaddr_in);
    ls->addr = offsetof(struct sockaddr_in, sin_addr);
    ls->addr_text_max_len = INET_ADDRSTRLEN;

    return ls;
}


ngx_int_t
ngx_set_inherited_sockets(ngx_cycle_t *cycle)
{
    size_t                     len;
    ngx_uint_t                 i;
    ngx_listening_t           *ls;
    struct sockaddr_in        *sin;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ngx_err_t                  err;
    socklen_t                  aflen;
    struct accept_filter_arg   af;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    socklen_t                  tlen;
    int                        timeout;
#endif

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

        sin = (struct sockaddr_in *) ls[i].sockaddr;

        if (sin->sin_family != AF_INET) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                          "the inherited socket #%d has "
                          "unsupported family", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        ls[i].addr_text_max_len = INET_ADDRSTRLEN;

        ls[i].addr_text.data = ngx_palloc(cycle->pool, INET_ADDRSTRLEN - 1
                                                       + sizeof(":65535") - 1);
        if (ls[i].addr_text.data == NULL) {
            return NGX_ERROR;
        }

        ls[i].family = sin->sin_family;
        len = ngx_sock_ntop(ls[i].family, ls[i].sockaddr,
                            ls[i].addr_text.data, INET_ADDRSTRLEN);
        if (len == 0) {
            return NGX_ERROR;
        }

        ls[i].addr_text.len = ngx_sprintf(ls[i].addr_text.data + len, ":%d",
                                          ntohs(sin->sin_port))
                              - ls[i].addr_text.data;

        ls[i].backlog = -1;

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

        ngx_memzero(&af, sizeof(struct accept_filter_arg));
        aflen = sizeof(struct accept_filter_arg);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &aflen)
            == -1)
        {
            err = ngx_errno;

            if (err == NGX_EINVAL) {
                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
                          "getsockopt(SO_ACCEPTFILTER) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (aflen < sizeof(struct accept_filter_arg) || af.af_name[0] == '\0') {
            continue;
        }

        ls[i].accept_filter = ngx_palloc(cycle->pool, 16);
        if (ls[i].accept_filter == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_cpystrn((u_char *) ls[i].accept_filter,
                           (u_char *) af.af_name, 16);
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

        timeout = 0;
        tlen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, &tlen)
            == -1)
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, ngx_errno,
                          "getsockopt(TCP_DEFER_ACCEPT) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (tlen < sizeof(int) || timeout == 0) {
            continue;
        }

        ls[i].deferred_accept = 1;
#endif
    }

    return NGX_OK;
}


ngx_int_t
ngx_open_listening_sockets(ngx_cycle_t *cycle)
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

            s = ngx_socket(ls[i].family, ls[i].type, 0);

            if (s == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_socket_n " %V failed", &ls[i].addr_text);
                return NGX_ERROR;
            }

#if (NGX_WIN32)

            /*
             * Winsock assignes a socket number divisible by 4
             * so to find a connection we divide a socket number by 4.
             */

            if (s % 4) {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              ngx_socket_n " created socket %d", s);
                return NGX_ERROR;
            }
#endif

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int)) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "setsockopt(SO_REUSEADDR) %V failed",
                              &ls[i].addr_text);
                return NGX_ERROR;
            }

            /* TODO: close on exit */

            if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %V failed",
                                  &ls[i].addr_text);
                    return NGX_ERROR;
                }
            }

#if 0
            if (ls[i].nonblocking) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %V failed",
                                  &ls[i].addr_text);
                    return NGX_ERROR;
                }
            }
#endif

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = ngx_socket_errno;
                ngx_log_error(NGX_LOG_EMERG, log, err,
                              "bind() to %V failed", &ls[i].addr_text);

                if (err != NGX_EADDRINUSE)
                    return NGX_ERROR;

                if (ngx_close_socket(s) == -1)
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls[i].addr_text);

                failed = 1;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "listen() to %V failed", &ls[i].addr_text);
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
        ngx_log_error(NGX_LOG_EMERG, log, 0, "still could not bind()");
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_close_listening_sockets(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        return;
    }

    ngx_accept_mutex_held = 0;
    ngx_accept_mutex = NULL;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            if (c->read->active) {
                ngx_del_conn(c, NGX_CLOSE_EVENT);
            }

        } else {
            if (c->read->active) {
                ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            }
        }

        ngx_free_connection(c);

        c->fd = (ngx_socket_t) -1;

        if (ngx_close_socket(ls[i].fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                          ngx_close_socket_n " %V failed", &ls[i].addr_text);
        }
    }
}


ngx_connection_t *
ngx_get_connection(ngx_socket_t s, ngx_log_t *log)
{
    ngx_connection_t *c;

    /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */

    if (ngx_cycle->files && (ngx_uint_t) s >= ngx_cycle->files_n) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "the new socket has number %d, "
                      "but only %ui files are available",
                      s, ngx_cycle->files_n);
        return NULL;
    }

    /* ngx_mutex_lock */

    c = ngx_cycle->free_connections;

    if (c == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "%ui worker_connections is not enough",
                      ngx_cycle->connection_n);

        /* ngx_mutex_unlock */

        return NULL;
    }

    ngx_cycle->free_connections = c->data;
    ngx_cycle->free_connection_n--;

    /* ngx_mutex_unlock */

    if (ngx_cycle->files) {
        ngx_cycle->files[s] = c;
    }

    return c;
}


void
ngx_free_connection(ngx_connection_t *c)
{
    /* ngx_mutex_lock */

    c->data = ngx_cycle->free_connections;
    ngx_cycle->free_connections = c;
    ngx_cycle->free_connection_n++;

    /* ngx_mutex_unlock */

    if (ngx_cycle->files) {
        ngx_cycle->files[c->fd] = NULL;
    }
}


void
ngx_close_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    if (c->fd == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

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

    ngx_free_connection(c);

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    if (ngx_close_socket(fd) == -1) {

        /* we use ngx_cycle->log because c->log was in c->pool */

        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }
}


ngx_int_t
ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text)
{
    ngx_uint_t  level;

    if (err == NGX_ECONNRESET
        && c->log_error == NGX_ERROR_IGNORE_ECONNRESET)
    {
        return 0;
    }

    if (err == 0
        || err == NGX_ECONNRESET
#if !(NGX_WIN32)
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
