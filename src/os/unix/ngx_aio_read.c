
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

ssize_t ngx_aio_read(ngx_connection_t *c, char *buf, size_t size)
{
    int           n;
    ngx_event_t  *rev;

    rev = c->read;

    if (!rev->ready) {
        ngx_log_error(NGX_LOG_ALERT, rev->log, 0, "SECOND AIO POST");
        return NGX_AGAIN;
    }

    ngx_log_debug(rev->log, "rev->complete: %d" _ rev->complete);
    ngx_log_debug(rev->log, "aio size: %d" _ size);

    if (!rev->complete) {
        ngx_memzero(&rev->aiocb, sizeof(struct aiocb));

        rev->aiocb.aio_fildes = c->fd;
        rev->aiocb.aio_buf = buf;
        rev->aiocb.aio_nbytes = size;

#if (HAVE_KQUEUE)
        rev->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
        rev->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        rev->aiocb.aio_sigevent.sigev_value.sigval_ptr = rev;
#endif

        if (aio_read(&rev->aiocb) == -1) {
            ngx_log_error(NGX_LOG_CRIT, rev->log, ngx_errno,
                          "aio_read() failed");
            rev->error = 1;
            return NGX_ERROR;
        }

        ngx_log_debug(rev->log, "aio_read: #%d OK" _ c->fd);

        rev->active = 1;
        rev->ready = 0;
    }

    rev->complete = 0;

    n = aio_error(&rev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, rev->log, ngx_errno, "aio_error() failed");
        rev->error = 1;
        return NGX_ERROR;
    }

    if (n != 0) {
        if (n == NGX_EINPROGRESS) {
            if (rev->ready) {
                ngx_log_error(NGX_LOG_ALERT, rev->log, n,
                              "aio_read() still in progress");
                rev->ready = 0;
            }
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_CRIT, rev->log, n, "aio_read() failed");
        rev->error = 1;
        rev->ready = 0;
        return NGX_ERROR;
    }

    n = aio_return(&rev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, rev->log, ngx_errno,
                      "aio_return() failed");

        rev->error = 1;
        rev->ready = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(rev->log, "aio_read: #%d %d" _ c->fd _ n);

    if (n == 0) {
        rev->eof = 1;
        rev->ready = 0;
    } else {
        rev->ready = 1;
    }

    rev->active = 0;

    return n;
}
