
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
    ngx_err_t           err;
    ngx_socket_t        s;
    struct sockaddr_in  addr;
    int addrlen = sizeof(struct sockaddr_in);
    ngx_connection_t *cn = (ngx_connection_t *) ev->data;
            
    ngx_log_debug(ev->log, "ngx_event_accept: accept ready: %d" _
                  ev->available);
        
    ev->ready = 0;
  
    do {
        if ((s = accept(cn->fd, cn->sockaddr, &cn->socklen)) == -1) {
            err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_INFO, ev->log, err,
                             "ngx_event_accept: EAGAIN while accept %s",
                             cn->addr_text);
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ERR, ev->log, err,
                         "ngx_event_accept: accept %s failed", cn->addr_text);
            /* if we return NGX_ERROR listen socket would be closed */
            return NGX_OK;
        }

        ngx_log_debug(ev->log, "ngx_event_accept: accept: %d" _ s);

#if !(HAVE_INHERITED_NONBLOCK)
        if (ngx_nonblocking(s) == -1)
            ngx_log_error(NGX_LOG_ERR, log, ngx_socket_errno,
                          ngx_nonblocking_n "failed");
#endif

        ngx_memzero(&ngx_read_events[s], sizeof(ngx_event_t));
        ngx_memzero(&ngx_write_events[s], sizeof(ngx_event_t));
        ngx_memzero(&ngx_connections[s], sizeof(ngx_connection_t));

        ngx_connections[s].sockaddr = cn->sockaddr;
        ngx_connections[s].family = cn->family;
        ngx_connections[s].socklen = cn->socklen;
        ngx_connections[s].addr = cn->addr;
        ngx_connections[s].addr_text.len = cn->addr_text.len;
        ngx_connections[s].post_accept_timeout = cn->post_accept_timeout;

        ngx_read_events[s].data = ngx_write_events[s].data
                                                         = &ngx_connections[s];
        ngx_connections[s].read = &ngx_read_events[s];
        ngx_connections[s].write = &ngx_write_events[s];

        ngx_connections[s].fd = s;
        ngx_connections[s].unexpected_eof = 1;
        ngx_write_events[s].write = 1;
        ngx_write_events[s].ready = 1;

        ngx_write_events[s].timer = ngx_read_events[s].timer = 10000;

        ngx_write_events[s].timer_handler =
            ngx_read_events[s].timer_handler = ngx_event_close_connection;

        ngx_write_events[s].close_handler =
            ngx_read_events[s].close_handler = ngx_event_close_connection;

        ngx_connections[s].server = cn->server;
        ngx_connections[s].servers = cn->servers;
        ngx_connections[s].log =
            ngx_read_events[s].log = ngx_write_events[s].log = ev->log;

#if (HAVE_DEFERRED_ACCEPT)
        if (ev->accept_filter)
            ngx_read_events[s].ready = 1;
#endif

        cn->handler(&ngx_connections[s]);

#if (HAVE_KQUEUE)
#if !(USE_KQUEUE)
        if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
            ev->available--;
#endif
    } while (ev->available);
  
    return 0;
}
