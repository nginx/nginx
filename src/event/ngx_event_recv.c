
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_recv.h>
#include <ngx_connection.h>

int ngx_event_recv_core(ngx_event_t *ev, char *buf, size_t size)
{
    int                n;
    ngx_err_t          err;
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    if (ev->timedout) {
        ngx_set_socket_errno(NGX_ETIMEDOUT);
        ngx_log_error(NGX_LOG_ERR, ev->log, NGX_ETIMEDOUT, "recv() failed");
        return NGX_ERROR;
    }

#if (HAVE_KQUEUE)
    ngx_log_debug(ev->log, "ngx_event_recv: eof:%d, avail:%d, err:%d" _
                  ev->eof _ ev->available _ ev->error);
#if !(USE_KQUEUE)
    if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
        if (ev->eof && ev->available == 0) {
            if (ev->error) {
                ngx_log_error(NGX_LOG_ERR, ev->log, ev->error, "recv() failed");
                return NGX_ERROR;
            }

            return 0;
        }
#endif

    n = ngx_recv(c->fd, buf, size, 0);

    if (n == -1) {
        err = ngx_socket_errno;

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, ev->log, err, "recv() returns EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, ev->log, err, "recv() failed");
        return NGX_ERROR;
    }

#if (HAVE_KQUEUE)
#if !(USE_KQUEUE)
    if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
        ev->available -= n;
#endif

    return n;
}
