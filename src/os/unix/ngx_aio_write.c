
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>

#if (NGX_HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif


/*
 * the ready data requires 3 syscalls:
 *     aio_write(), aio_error(), aio_return()
 * the non-ready data requires 4 (kqueue) or 5 syscalls:
 *     aio_write(), aio_error(), notifiction, aio_error(), aio_return()
 *                               timeout, aio_cancel(), aio_error()
 */

ssize_t
ngx_aio_write(ngx_connection_t *c, u_char *buf, size_t size)
{
    int           n;
    ngx_event_t  *wev;

    wev = c->write;

    if (!wev->ready) {
        return NGX_AGAIN;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, wev->log, 0,
                   "aio: wev->complete: %d", wev->complete);

    if (!wev->complete) {
        ngx_memzero(&wev->aiocb, sizeof(struct aiocb));

        wev->aiocb.aio_fildes = c->fd;
        wev->aiocb.aio_buf = buf;
        wev->aiocb.aio_nbytes = size;

#if (NGX_HAVE_KQUEUE)
        wev->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
        wev->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        wev->aiocb.aio_sigevent.sigev_value.sigval_ptr = wev;
#endif

        if (aio_write(&wev->aiocb) == -1) {
            ngx_log_error(NGX_LOG_CRIT, wev->log, ngx_errno,
                          "aio_write() failed");
            return NGX_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, wev->log, 0, "aio_write: OK");

        wev->active = 1;
        wev->ready = 0;
    }

    wev->complete = 0;

    n = aio_error(&wev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, wev->log, ngx_errno, "aio_error() failed");
        wev->error = 1;
        return NGX_ERROR;
    }

    if (n != 0) {
        if (n == NGX_EINPROGRESS) {
            if (wev->ready) {
                ngx_log_error(NGX_LOG_ALERT, wev->log, n,
                              "aio_write() still in progress");
                wev->ready = 0;
            }
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_CRIT, wev->log, n, "aio_write() failed");
        wev->error = 1;
        wev->ready = 0;

#if 1
        n = aio_return(&wev->aiocb);
        if (n == -1) {
            ngx_log_error(NGX_LOG_ALERT, wev->log, ngx_errno,
                          "aio_return() failed");
        }

        ngx_log_error(NGX_LOG_CRIT, wev->log, n, "aio_return() %d", n);
#endif

        return NGX_ERROR;
    }

    n = aio_return(&wev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, wev->log, ngx_errno,
                      "aio_return() failed");

        wev->error = 1;
        wev->ready = 0;
        return NGX_ERROR;
    }


    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, wev->log, 0, "aio_write: %d", n);

    wev->active = 0;
    wev->ready = 1;

    return n;
}
