
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_close.h>
#include <ngx_event_accept.h>


int ngx_event_accept(ngx_event_t *ev)
{
    ngx_err_t          err;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c, *ac;

    ac = (ngx_connection_t *) ev->data;
            
    ngx_log_debug(ev->log, "ngx_event_accept: accept ready: %d" _
                  ev->available);
        
    ev->ready = 0;
  
    do {
        if ((s = accept(ac->fd, ac->sockaddr, &ac->socklen)) == -1) {
            err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_INFO, ev->log, err,
                             "ngx_event_accept: EAGAIN while accept %s",
                             ac->addr_text);
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ERR, ev->log, err,
                         "ngx_event_accept: accept %s failed", ac->addr_text);
            /* if we return NGX_ERROR listen socket would be closed */
            return NGX_OK;
        }

#if !(HAVE_INHERITED_NONBLOCK)
        if (ngx_nonblocking(s) == -1)
            ngx_log_error(NGX_LOG_ERR, log, ngx_socket_errno,
                          ngx_nonblocking_n "failed");
#endif

        rev = &ngx_read_events[s];
        wev = &ngx_write_events[s];
        c = &ngx_connections[s];

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));
        ngx_memzero(c, sizeof(ngx_connection_t));

        c->sockaddr = ac->sockaddr;
        c->family = ac->family;
        c->socklen = ac->socklen;
        c->addr = ac->addr;
        c->addr_text.len = ac->addr_text.len;
        c->post_accept_timeout = ac->post_accept_timeout;

        rev->index = wev->index = NGX_INVALID_INDEX;

        rev->data = wev->data = c;
        c->read = rev;
        c->write = wev;

        c->fd = s;
        c->unexpected_eof = 1;
        wev->write = 1;
        wev->ready = 1;

        wev->timer = rev->timer = 10000;
        wev->timer_handler = rev->timer_handler = ngx_event_close_connection;
        wev->close_handler = rev->close_handler = ngx_event_close_connection;

        c->server = ac->server;
        c->servers = ac->servers;
        c->log = rev->log = wev->log = ev->log;

        /* STUB: x86: SP: xadd, MT: lock xadd, MP: lock xadd, shared */
        c->number = ngx_connection_counter++;

        ngx_log_debug(ev->log, "ngx_event_accept: accept: %d, %d" _
                                s _ c->number);

#if (HAVE_DEFERRED_ACCEPT)
        if (ev->accept_filter)
            rev->ready = 1;
#endif

        ac->handler(c);

#if (HAVE_KQUEUE)
#if !(USE_KQUEUE)
        if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
            ev->available--;
#endif
    } while (ev->available);
  
    return 0;
}
