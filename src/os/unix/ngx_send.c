
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *wev;

    wev = c->write;

#if (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) && wev->pending_eof) {
        ngx_log_error(NGX_LOG_INFO, c->log, wev->kq_errno,
                      "kevent() reported about an closed connection");

        wev->error = 1;
        return NGX_ERROR;
    }

#endif

    for ( ;; ) {
        n = send(c->fd, buf, size, 0);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "send: fd:%d %d of %d", c->fd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                wev->ready = 0;
            }

            return n;
        }

        err = ngx_socket_errno;

        if (n == 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, err, "send() returned zero");
            wev->ready = 0;
            return n;
        }

        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            wev->ready = 0;

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "send() not ready");

            if (err == NGX_EAGAIN) {
                return NGX_AGAIN;
            }

        } else {
            wev->error = 1;
            ngx_connection_error(c, err, "recv() failed");
            return NGX_ERROR;
        }
    }
}
