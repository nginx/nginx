
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_recv.h>
#include <ngx_connection.h>

ssize_t ngx_event_recv_core(ngx_connection_t *c, char *buf, size_t size)
{
    int                n;
    ngx_err_t          err;
    ngx_event_t       *ev;

    ev = c->read;

    if (ev->timedout) {
        ngx_set_socket_errno(NGX_ETIMEDOUT);
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "recv() failed");
        return NGX_ERROR;
    }

#if (HAVE_KQUEUE)
    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ngx_log_debug(c->log, "ngx_event_recv: eof:%d, avail:%d, err:%d" _
                      ev->eof _ ev->available _ ev->error);
    }
#endif

#if (USE_KQUEUE)

    if (ev->eof && ev->available == 0) {
        if (ev->error) {
            ngx_set_socket_errno(ev->error);

            if (ev->error == NGX_ECONNRESET && ev->ignore_econnreset) {
                return 0;
            }

            ngx_log_error(NGX_LOG_ERR, c->log, ev->error,
                          "recv() failed");
            return NGX_ERROR;
        }

        return 0;
    }

#elif (HAVE_KQUEUE)

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        if (ev->eof && ev->available == 0) {
            if (ev->error) {
                ngx_set_socket_errno(ev->error);

                if (ev->error == NGX_ECONNRESET && ev->ignore_econnreset) {
                    return 0;
                }

                ngx_log_error(NGX_LOG_ERR, c->log, ev->error,
                              "recv() failed");
                return NGX_ERROR;
            }

            return 0;
        }
    }

#endif

    n = ngx_recv(c->fd, buf, size, 0);

    if (n == -1) {
        err = ngx_socket_errno;

        if (ev->error == NGX_ECONNRESET && ev->ignore_econnreset) {
            return 0;
        }

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "recv() returns EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "recv() failed");
        return NGX_ERROR;
    }

#if (USE_KQUEUE)

    ev->available -= n;

#elif (HAVE_KQUEUE)

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ev->available -= n;
    }

#endif

    return n;
}
