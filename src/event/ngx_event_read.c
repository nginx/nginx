
#include <ngx_config.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_connection.h>

int ngx_event_recv(ngx_connection_t *c, char *buf, size_t size)
{
    int           n;
    ngx_err_t     err;
    ngx_event_t  *ev = c->read;

#if (HAVE_KQUEUE)
#if !(USE_KQUEUE)
    if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
        if (ev->eof && ev->available == 0) {
            if (ev->error) {
                ngx_log_error(NGX_LOG_ERR, ev->log, ev->error,
                             "ngx_event_recv: recv failed while %s",
                             ev->log->action);

                return -1;
            }

            return 0;
        }
#endif

    n = recv(c->fd, buf, size, 0);

    if (n == -1) {
        err = ngx_socket_errno;

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, ev->log, err,
                          "ngx_event_recv: EAGAIN while %s", ev->log->action);
            return -2;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "ngx_event_recv: recv failed while %s", ev->log->action);

        return -1;
    }

#if (HAVE_KQUEUE)
#if !(USE_KQUEUE)
    if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
        ev->available -= n;
#endif

    return n;
}
