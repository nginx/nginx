
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


void ngx_event_acceptex(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "AcceptEx: %d", c->fd);

    if (rev->ovlp.error) {
        ngx_log_error(NGX_LOG_CRIT, c->log, rev->ovlp.error,
                      "AcceptEx() %V failed", &c->listening->addr_text);
        return;
    }

    /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */

    if (setsockopt(c->fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                   (char *) &c->listening->fd, sizeof(ngx_socket_t)) == -1)
    {
        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                      "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed for %V",
                      &c->addr_text);
    } else {
        c->accept_context_updated = 1;
    }

    getacceptexsockaddrs(c->buffer->pos, c->listening->post_accept_buffer_size,
                         c->listening->socklen + 16,
                         c->listening->socklen + 16,
                         &c->local_sockaddr, &c->local_socklen,
                         &c->sockaddr, &c->socklen);

    if (c->listening->post_accept_buffer_size) {
        c->buffer->last += rev->available;
        c->buffer->end = c->buffer->start
                                       + c->listening->post_accept_buffer_size;

    } else {
        c->buffer = NULL;
    }

    if (c->listening->addr_ntop) {
        c->addr_text.data = ngx_palloc(c->pool,
                                       c->listening->addr_text_max_len);
        if (c->addr_text.data == NULL) {
            /* TODO: close socket */
            return;
        }

        c->addr_text.len = ngx_sock_ntop(c->listening->family, c->sockaddr,
                                         c->addr_text.data,
                                         c->listening->addr_text_max_len);
        if (c->addr_text.len == 0) {
            /* TODO: close socket */
            return;
        }
    }

    ngx_event_post_acceptex(c->listening, 1);

    c->number = ngx_atomic_inc(ngx_connection_counter);

    c->listening->handler(c);

    return;

}


int ngx_event_post_acceptex(ngx_listening_t *ls, int n)
{
    u_long             rcvd;
    ngx_int_t          i;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_connection_t  *c;

    for (i = 0; i < n; i++) {

        /* TODO: look up reused sockets */

        s = ngx_socket(ls->family, ls->type, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ls->log, 0,
                       ngx_socket_n " s:%d", s);

        if (s == -1) {
            ngx_log_error(NGX_LOG_ALERT, ls->log, ngx_socket_errno,
                          ngx_socket_n " for AcceptEx() %s post failed",
                          ls->addr_text.data);

            return NGX_ERROR;
        }

        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        if (s % 4) {
            ngx_log_error(NGX_LOG_EMERG, ls->log, 0,
                          ngx_socket_n
                          " created socket %d, not divisible by 4", s);

            exit(1);
        }

        c = &ngx_cycle->connections[s / 4];
        rev = &ngx_cycle->read_events[s / 4];
        wev = &ngx_cycle->write_events[s / 4];

        ngx_memzero(c, sizeof(ngx_connection_t));
        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));

        c->listening = ls;

        rev->index = NGX_INVALID_INDEX;
        wev->index = NGX_INVALID_INDEX;

        rev->ovlp.event = rev;
        wev->ovlp.event = wev;
        rev->handler = ngx_event_acceptex;

        rev->data = c;
        wev->data = c;

        c->read = rev;
        c->write = wev;

        c->fd = s;
        c->unexpected_eof = 1;

        rev->ready = 1;
        wev->write = 1;
        wev->ready = 1;

        c->ctx = ls->ctx;
        c->servers = ls->servers;

        c->recv = ngx_recv;
        c->send = ngx_send;
        c->send_chain = ngx_send_chain;

        c->pool = ngx_create_pool(ls->pool_size, ls->log);
        if (c->pool == NULL) {
            return NGX_ERROR;
        }

        c->buffer = ngx_create_temp_buf(c->pool,
                                        ls->post_accept_buffer_size
                                        + 2 * (c->listening->socklen + 16));
        if (c->buffer == NULL) {
            return NGX_ERROR;
        }

        c->local_sockaddr = ngx_palloc(c->pool, ls->socklen);
        if (c->local_sockaddr == NULL) {
            return NGX_ERROR;
        }

        c->sockaddr = ngx_palloc(c->pool, ls->socklen);
        if (c->sockaddr == NULL) {
            return NGX_ERROR;
        }

        c->log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (c->log == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(c->log, ls->log, sizeof(ngx_log_t));
        c->read->log = c->log;
        c->write->log = c->log;

        if (ngx_add_event(rev, 0, NGX_IOCP_IO) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (acceptex(ls->fd, s, c->buffer->pos, ls->post_accept_buffer_size,
                     ls->socklen + 16, ls->socklen + 16,
                     &rcvd, (LPOVERLAPPED) &rev->ovlp) == 0)
        {

            err = ngx_socket_errno;
            if (err != WSA_IO_PENDING) {
                ngx_log_error(NGX_LOG_ALERT, ls->log, err,
                              "AcceptEx() %s falied", ls->addr_text.data);

                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}
