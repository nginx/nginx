
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>
#include <ngx_event_close.h>


int ngx_event_close_connection(ngx_event_t *ev)
{
    int rc;
    ngx_connection_t *c = (ngx_connection_t *) ev->data;

    ngx_log_debug(c->log, "close connection: %d" _ c->fd);

    ngx_assert((c->fd != -1), return NGX_ERROR, c->log,
               "ngx_event_close: already closed");

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
        c->read->timer_set = 0;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
        c->write->timer_set = 0;
    }

    ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
    ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);

    if ((rc = ngx_close_socket(c->fd)) == -1)
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      "ngx_event_close: close failed");

    c->fd = -1;

    ngx_destroy_pool(c->pool);

    return rc;
}
