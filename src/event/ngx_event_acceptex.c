
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void ngx_close_posted_connection(ngx_connection_t *c);


void
ngx_event_acceptex(ngx_event_t *rev)
{
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    c = rev->data;
    ls = c->listening;

    c->log->handler = ngx_accept_log_error;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "AcceptEx: %d", c->fd);

    if (rev->ovlp.error) {
        ngx_log_error(NGX_LOG_CRIT, c->log, rev->ovlp.error,
                      "AcceptEx() %V failed", &ls->addr_text);
        return;
    }

    /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */

    if (setsockopt(c->fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                   (char *) &ls->fd, sizeof(ngx_socket_t))
        == -1)
    {
        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                      "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed for %V",
                      &c->addr_text);
    } else {
        c->accept_context_updated = 1;
    }

    ngx_getacceptexsockaddrs(c->buffer->pos,
                             ls->post_accept_buffer_size,
                             ls->socklen + 16,
                             ls->socklen + 16,
                             &c->local_sockaddr, &c->local_socklen,
                             &c->sockaddr, &c->socklen);

    if (ls->post_accept_buffer_size) {
        c->buffer->last += rev->available;
        c->buffer->end = c->buffer->start + ls->post_accept_buffer_size;

    } else {
        c->buffer = NULL;
    }

    if (ls->addr_ntop) {
        c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
        if (c->addr_text.data == NULL) {
            /* TODO: close socket */
            return;
        }

        c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                         c->addr_text.data,
                                         ls->addr_text_max_len, 0);
        if (c->addr_text.len == 0) {
            /* TODO: close socket */
            return;
        }
    }

    ngx_event_post_acceptex(ls, 1);

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    ls->handler(c);

    return;

}


ngx_int_t
ngx_event_post_acceptex(ngx_listening_t *ls, ngx_uint_t n)
{
    u_long             rcvd;
    ngx_err_t          err;
    ngx_log_t         *log;
    ngx_uint_t         i;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_connection_t  *c;

    for (i = 0; i < n; i++) {

        /* TODO: look up reused sockets */

        s = ngx_socket(ls->sockaddr->sa_family, ls->type, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &ls->log, 0,
                       ngx_socket_n " s:%d", s);

        if (s == (ngx_socket_t) -1) {
            ngx_log_error(NGX_LOG_ALERT, &ls->log, ngx_socket_errno,
                          ngx_socket_n " failed");

            return NGX_ERROR;
        }

        c = ngx_get_connection(s, &ls->log);

        if (c == NULL) {
            return NGX_ERROR;
        }

        c->pool = ngx_create_pool(ls->pool_size, &ls->log);
        if (c->pool == NULL) {
            ngx_close_posted_connection(c);
            return NGX_ERROR;
        }

        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_posted_connection(c);
            return NGX_ERROR;
        }

        c->buffer = ngx_create_temp_buf(c->pool, ls->post_accept_buffer_size
                                                 + 2 * (ls->socklen + 16));
        if (c->buffer == NULL) {
            ngx_close_posted_connection(c);
            return NGX_ERROR;
        }

        c->local_sockaddr = ngx_palloc(c->pool, ls->socklen);
        if (c->local_sockaddr == NULL) {
            ngx_close_posted_connection(c);
            return NGX_ERROR;
        }

        c->sockaddr = ngx_palloc(c->pool, ls->socklen);
        if (c->sockaddr == NULL) {
            ngx_close_posted_connection(c);
            return NGX_ERROR;
        }

        *log = ls->log;
        c->log = log;

        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;

        c->unexpected_eof = 1;

        c->listening = ls;

        rev = c->read;
        wev = c->write;

        rev->ovlp.event = rev;
        wev->ovlp.event = wev;
        rev->handler = ngx_event_acceptex;

        rev->ready = 1;
        wev->ready = 1;

        rev->log = c->log;
        wev->log = c->log;

        if (ngx_add_event(rev, 0, NGX_IOCP_IO) == NGX_ERROR) {
            ngx_close_posted_connection(c);
            return NGX_ERROR;
        }

        if (ngx_acceptex(ls->fd, s, c->buffer->pos, ls->post_accept_buffer_size,
                         ls->socklen + 16, ls->socklen + 16,
                         &rcvd, (LPOVERLAPPED) &rev->ovlp)
            == 0)
        {
            err = ngx_socket_errno;
            if (err != WSA_IO_PENDING) {
                ngx_log_error(NGX_LOG_ALERT, &ls->log, err,
                              "AcceptEx() %V falied", &ls->addr_text);

                ngx_close_posted_connection(c);
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static void
ngx_close_posted_connection(ngx_connection_t *c)
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
}


u_char *
ngx_acceptex_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    return ngx_snprintf(buf, len, " while posting AcceptEx() on %V", log->data);
}
