
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_recv.h>
#include <ngx_connection.h>

int ngx_event_recv_core(ngx_connection_t *c, char *buf, size_t size)
{
    int                n;
    ngx_err_t          err;

    if (c->read->timedout) {
        ngx_set_socket_errno(NGX_ETIMEDOUT);
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "recv() failed");
        return NGX_ERROR;
    }

#if (HAVE_KQUEUE)
    ngx_log_debug(c->log, "ngx_event_recv: eof:%d, avail:%d, err:%d" _
                  c->read->eof _ c->read->available _ c->read->error);
#if !(USE_KQUEUE)
    if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
        if (c->read->eof && c->read->available == 0) {
            if (c->read->error) {
                ngx_log_error(NGX_LOG_ERR, c->log, c->read->error,
                              "recv() failed");
                return NGX_ERROR;
            }

            return 0;
        }
#endif

    n = ngx_recv(c->fd, buf, size, 0);

    if (n == -1) {
        err = ngx_socket_errno;

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "recv() returns EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "recv() failed");
        return NGX_ERROR;
    }

#if (HAVE_KQUEUE)
#if !(USE_KQUEUE)
    if (ngx_event_type == NGX_KQUEUE_EVENT)
#endif
        c->read->available -= n;
#endif

    return n;
}
