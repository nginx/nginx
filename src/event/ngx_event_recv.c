
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_recv.h>
#include <ngx_connection.h>

ssize_t ngx_event_recv_core(ngx_connection_t *c, char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *ev;

    ev = c->read;

/* DEBUG */
#if (HAVE_KQUEUE)
    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ngx_log_debug(c->log, "ngx_event_recv: eof:%d, avail:%d, err:%d" _
                      ev->eof _ ev->available _ ev->error);
    }
#endif

#if (USE_KQUEUE)

    if (ev->eof && ev->available == 0) {

        if (ev->error == 0) {
            return 0;
        }

        ngx_set_socket_errno(ev->error);
        err = ev->error;
        n = -1;

    } else {
        n = ngx_recv(c->fd, buf, size, 0);

        if (n == -1) {
            err = ngx_socket_errno;
        }
    }

    if (n == -1) {
        ev->ready = 0;

        if (err == NGX_ECONNRESET && ev->ignore_econnreset) {
            return 0;
        }

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "recv() returned EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "recv() failed");
        return NGX_ERROR;
    }

    ev->available -= n;
    if (ev->available == 0) {
        ev->ready = 0;
    }

    return n;

#elif (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)
        && ev->eof && ev->available == 0) {

        if (ev->error == 0) {
            return 0;
        }

        ngx_set_socket_errno(ev->error);
        err = ev->error;
        n = -1;

    } else {
        n = ngx_recv(c->fd, buf, size, 0);
ngx_log_debug(c->log, "ngx_event_recv: read:%d:%d" _ n _ size);

        if (n == -1) {
            err = ngx_socket_errno;
        }
    }

    if (n == -1) {
        ev->ready = 0;

        if (err == NGX_ECONNRESET && ev->ignore_econnreset) {
            return 0;
        }

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "recv() returned EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "recv() failed");
        return NGX_ERROR;
    }

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ev->available -= n;
        if (ev->available == 0) {
            ev->ready = 0;
        }

    } else if ((size_t) n < size) {
        ev->ready = 0;
    }

    return n;

#else /* not kqueue */

    n = ngx_recv(c->fd, buf, size, 0);

    if (n == -1) {
        err = ngx_socket_errno;

        ev->ready = 0;

        if (err == NGX_ECONNRESET && ev->ignore_econnreset) {
            return 0;
        }

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "recv() returned EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "recv() failed");
        return NGX_ERROR;
    }

    if ((size_t) n < size) {
        ev->ready = 0;
    }

    return n;

#endif
}
