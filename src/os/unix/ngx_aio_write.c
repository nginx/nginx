
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif


/*
 * the ready data requires 3 syscalls:
 *     aio_write(), aio_error(), aio_return()
 * the non-ready data requires 4 (kqueue) or 5 syscalls:
 *     aio_write(), aio_error(), notifiction, aio_error(), aio_return()
 *                               timeout, aio_cancel(), aio_error()
 */

ssize_t ngx_aio_write(ngx_connection_t *c, char *buf, size_t size)
{
    int           n;
    ngx_event_t  *wev;

    wev = c->write;

    if (wev->active) {
        return NGX_AGAIN;
    }

ngx_log_debug(wev->log, "aio: wev->aio_complete: %d" _ wev->aio_complete);

    if (!wev->aio_complete) {
        ngx_memzero(&wev->aiocb, sizeof(struct aiocb));

        wev->aiocb.aio_fildes = c->fd;
        wev->aiocb.aio_buf = buf;
        wev->aiocb.aio_nbytes = size;

#if (HAVE_KQUEUE)
        wev->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
        wev->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        wev->aiocb.aio_sigevent.sigev_value.sigval_ptr = wev;
#endif

        if (aio_write(&wev->aiocb) == -1) {
            ngx_log_error(NGX_LOG_CRIT, wev->log, ngx_errno,
                          "aio_write() failed");
            return NGX_ERROR;
        }

        ngx_log_debug(wev->log, "aio_write: OK");

        wev->active = 1;
    }

    wev->aio_complete = 0;

    n = aio_error(&wev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, wev->log, ngx_errno, "aio_error() failed");
        wev->error = 1;
        return NGX_ERROR;
    }

    if (n != 0) {
        if (n == NGX_EINPROGRESS) {
            if (!wev->active) {
                ngx_log_error(NGX_LOG_ALERT, wev->log, n,
                              "aio_write() still in progress");
            }
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_CRIT, wev->log, n, "aio_write() failed");
        wev->error = 1;
        return NGX_ERROR;
    }

    n = aio_return(&wev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, wev->log, ngx_errno,
                      "aio_return() failed");

        wev->error = 1;
        return NGX_ERROR;
    }

    wev->active = 0;

    ngx_log_debug(wev->log, "aio_write: %d" _ n);

    if (n == 0) {
        wev->eof = 1;
    }

    return n;
}
