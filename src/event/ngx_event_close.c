
#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_connection.h>
#include <ngx_event_close.h>


int ngx_event_close_connection(ngx_event_t *ev)
{
    int rc;
    ngx_connection_t *cn = (ngx_connection_t *) ev->data;

    ngx_assert((cn->fd != -1), return -1, ev->log,
               "ngx_event_close: already closed");

    if ((rc = ngx_close_socket(cn->fd)) == -1)
        ngx_log_error(NGX_LOG_ERR, ev->log, ngx_socket_errno,
                      "ngx_event_close: close failed");

    if (cn->read->next)
        ngx_del_event(cn->read, NGX_READ_EVENT);

    if (cn->write->next)
        ngx_del_event(cn->write, NGX_WRITE_EVENT);

    cn->fd = -1;

    return rc;
}
