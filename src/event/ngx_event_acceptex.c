
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_listen.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_close.h>
#include <ngx_iocp_module.h>

#include <ngx_event_acceptex.h>



/* This function should always return NGX_OK even there are some failures
   because if we return NGX_ERROR then listening socket would be closed */

int ngx_event_acceptex(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    if (ev->ovlp.error) {
        ngx_log_error(NGX_LOG_CRIT, ev->log, ev->ovlp.error,
                      "AcceptEx(%s) falied", c->addr_text.data);
        return NGX_OK;
    }

    getacceptexsockaddrs(c->data, 0,
                         c->socklen + 16, c->socklen + 16,
                         &c->local_sockaddr, &c->local_socklen,
                         &c->sockaddr, &c->socklen);

    ngx_event_post_acceptex(c->listening, 1);

    /* STUB: InterlockedInc() */
    c->number = ngx_connection_counter++;

    c->handler(c);

    return NGX_OK;

}


int ngx_event_post_acceptex(ngx_listen_t *ls, int n)
{
    int                i;
    u_int              rcvd;
    ngx_err_t          err;
    ngx_pool_t        *pool;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_connection_t  *c;

    for (i = 0; i < n; i++) {

        /* TODO: look up reused sockets */

        ngx_log_debug(ls->log, "socket: %x" _ ls->flags);

        s = ngx_socket(ls->family, ls->type, ls->protocol, ls->flags);

        if (s == -1) {
            ngx_log_error(NGX_LOG_ALERT, ls->log, ngx_socket_errno,
                          ngx_socket_n " for AcceptEx(%s) falied",
                          ls->addr_text.data);

            return NGX_ERROR;
        }

        ngx_test_null(pool, ngx_create_pool(ls->pool_size, ls->log), NGX_ERROR);

        rev = &ngx_read_events[s];
        wev = &ngx_write_events[s];
        c = &ngx_connections[s];

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));
        ngx_memzero(c, sizeof(ngx_connection_t));

        c->pool = pool;

        rev->index = wev->index = NGX_INVALID_INDEX;

        rev->ovlp.event = rev;
        wev->ovlp.event = wev;

        rev->data = wev->data = c;
        c->read = rev;
        c->write = wev;

        c->family = ls->family;
        c->socklen = ls->socklen;
        c->addr = ls->addr;
        c->addr_text_max_len = ls->addr_text_max_len;
        c->post_accept_timeout = ls->post_accept_timeout;

        c->listening = ls;
        c->fd = s;

        c->unexpected_eof = 1;
        wev->write = 1;

        c->handler = ls->handler;
        rev->event_handler = ngx_event_acceptex;

        wev->timer_handler = rev->timer_handler = ngx_event_close_connection;
        wev->close_handler = rev->close_handler = ngx_event_close_connection;

        c->ctx = ls->ctx;
        c->servers = ls->servers;

        ngx_test_null(c->data, ngx_palloc(pool, 2 * (c->socklen + 16)),
                      NGX_ERROR);
        ngx_test_null(c->local_sockaddr, ngx_palloc(pool, c->socklen),
                      NGX_ERROR);
        ngx_test_null(c->sockaddr, ngx_palloc(pool, c->socklen),
                      NGX_ERROR);

        ngx_test_null(c->log, ngx_palloc(c->pool, sizeof(ngx_log_t)),
                      NGX_ERROR);
        ngx_memcpy(c->log, ls->log, sizeof(ngx_log_t));
        rev->log = wev->log = c->log;

        if (ngx_iocp_add_event(rev) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (acceptex(ls->fd, s, c->data, 0,
                     c->socklen + 16, c->socklen + 16,
                     &rcvd, (LPOVERLAPPED) &rev->ovlp) == 0) {

            err = ngx_socket_errno;
            if (err == WSA_IO_PENDING) {
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ALERT, ls->log, err,
                          "AcceptEx(%s) falied", ls->addr_text.data);

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
