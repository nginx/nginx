
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


void ngx_event_acceptex(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) rev->data;

    if (rev->ovlp.error) {
        ngx_log_error(NGX_LOG_CRIT, c->log, rev->ovlp.error,
                      "AcceptEx() %s failed", c->listening->addr_text.data);
        return;
    }

    /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */

    if (setsockopt(c->fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                   (char *)&c->listening->fd, sizeof(ngx_socket_t)) == -1)
    {
        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                      "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed for %s",
                      c->addr_text.data);
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

        s = ngx_socket(ls->family, ls->type, ls->protocol, ls->flags);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ls->log, 0,
                       ngx_socket_n " s:%d fl:%d", s, ls->flags);

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

        rev->index = wev->index = NGX_INVALID_INDEX;

        rev->ovlp.event = rev;
        wev->ovlp.event = wev;

        rev->data = wev->data = c;
        c->read = rev;
        c->write = wev;

        c->listening = ls;
        c->fd = s;

        c->ctx = ls->ctx;
        c->servers = ls->servers;

        c->unexpected_eof = 1;
        wev->write = 1;
        rev->event_handler = ngx_event_acceptex;

        rev->ready = 1;
        wev->ready = 1;

        ngx_test_null(c->pool,
                      ngx_create_pool(ls->pool_size, ls->log),
                      NGX_ERROR);

        ngx_test_null(c->buffer,
                      ngx_create_temp_buf(c->pool,
                                          ls->post_accept_buffer_size
                                          + 2 * (c->listening->socklen + 16)),
                      NGX_ERROR);

        ngx_test_null(c->local_sockaddr, ngx_palloc(c->pool, ls->socklen),
                      NGX_ERROR);

        ngx_test_null(c->sockaddr, ngx_palloc(c->pool, ls->socklen),
                      NGX_ERROR);

        ngx_test_null(c->log, ngx_palloc(c->pool, sizeof(ngx_log_t)),
                      NGX_ERROR);

        ngx_memcpy(c->log, ls->log, sizeof(ngx_log_t));
        c->read->log = c->write->log = c->log;

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
