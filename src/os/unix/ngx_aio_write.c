
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_aio.h>

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif


/*
    The data is ready - 3 syscalls:
        aio_write(), aio_error(), aio_return()
    The data is not ready - 4 (kqueue) or 5 syscalls:
        aio_write(), aio_error(), notifiction,
                                             aio_error(), aio_return()
                                             aio_cancel(), aio_error()
*/

ssize_t ngx_aio_write(ngx_connection_t *c, char *buf, size_t size)
{
    int           rc, first, canceled;
    ngx_event_t  *ev;

    ev = c->write;

    canceled = 0;

ngx_log_debug(ev->log, "aio: ev->ready: %d" _ ev->ready);
ngx_log_debug(ev->log, "aio: aiocb: %08x" _ &ev->aiocb);

    if (ev->timedout) {
        ngx_set_socket_errno(NGX_ETIMEDOUT);
        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "aio_write() timed out");

        rc = aio_cancel(c->fd, &ev->aiocb);
        if (rc == -1) {
            ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno,
                          "aio_cancel() failed");
            return NGX_ERROR;
        }

        ngx_log_debug(ev->log, "aio_cancel: %d" _ rc);

        canceled = 1;

        ev->ready = 1;
    }

    first = 0;

    if (!ev->ready) {
        ngx_memzero(&ev->aiocb, sizeof(struct aiocb));

        ev->aiocb.aio_fildes = c->fd;
        ev->aiocb.aio_buf = buf;
        ev->aiocb.aio_nbytes = size;

#if (HAVE_KQUEUE)
        ev->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
        ev->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        ev->aiocb.aio_sigevent.sigev_value.sigval_ptr = ev;
#endif

        if (aio_write(&ev->aiocb) == -1) {
            ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno,
                          "aio_write() failed");
            return NGX_ERROR;
        }

        ngx_log_debug(ev->log, "aio_write: OK");

        ev->active = 1;
        first = 1;
    }

    ev->ready = 0;

    rc = aio_error(&ev->aiocb);
    if (rc == -1) {
        ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno, "aio_error() failed");
        return NGX_ERROR;
    }

    if (rc != 0) {
        if (rc == NGX_EINPROGRESS) {
            if (!first) {
                ngx_log_error(NGX_LOG_CRIT, ev->log, rc,
                              "aio_write() still in progress");
            }
            return NGX_AGAIN;
        }

        if (rc == NGX_ECANCELED && canceled) {
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_CRIT, ev->log, rc, "aio_write() failed");
        return NGX_ERROR;
    }

    rc = aio_return(&ev->aiocb);
    if (rc == -1) {
        ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno, "aio_return() failed");

        return NGX_ERROR;
    }

    ngx_log_debug(ev->log, "aio_write: %d" _ rc);

    return rc;
}
