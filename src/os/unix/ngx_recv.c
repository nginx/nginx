
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_recv.h>
#include <ngx_connection.h>


ssize_t ngx_unix_recv(ngx_connection_t *c, char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *ev;

    ev = c->read;

#if (HAVE_KQUEUE) /* DEBUG */
    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ngx_log_debug(c->log, "ngx_recv: eof:%d, avail:%d, err:%d" _
                      ev->eof _ ev->available _ ev->error);
    }
#endif

#if (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)
        && ev->eof && ev->available == 0) {

        if (ev->error == 0) {
            return 0;
        }

        ngx_set_socket_errno(ev->error);
        err = ev->error;
        n = -1;

    } else {
        n = recv(c->fd, buf, size, 0);

ngx_log_debug(c->log, "ngx_recv: read:%d:%d" _ n _ size);

        if (n == -1) {
            err = ngx_socket_errno;
        }
    }

#else /* not kqueue */

    n = recv(c->fd, buf, size, 0);

    if (n == -1) {
        err = ngx_socket_errno;
    }

#endif

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

#if (HAVE_KQUEUE)

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ev->available -= n;
        if (ev->available == 0) {
            ev->ready = 0;
        }

        return n;
    }

#endif

    if ((size_t) n < size) {
        ev->ready = 0;
    }

    return n;
}
