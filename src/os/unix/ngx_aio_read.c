
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


extern int  ngx_kqueue;


ssize_t
ngx_aio_read(ngx_connection_t *c, u_char *buf, size_t size)
{
    int           n;
    ngx_event_t  *rev;

    rev = c->read;

    if (!rev->ready) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "second aio post");
        return NGX_AGAIN;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "rev->complete: %d", rev->complete);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "aio size: %d", size);

    if (!rev->complete) {
        ngx_memzero(&rev->aiocb, sizeof(struct aiocb));

        rev->aiocb.aio_fildes = c->fd;
        rev->aiocb.aio_buf = buf;
        rev->aiocb.aio_nbytes = size;

#if (NGX_HAVE_KQUEUE)
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

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "aio_read: #%d OK", c->fd);

        rev->active = 1;
        rev->ready = 0;
    }

    rev->complete = 0;

    n = aio_error(&rev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno, "aio_error() failed");
        rev->error = 1;
        return NGX_ERROR;
    }

    if (n != 0) {
        if (n == NGX_EINPROGRESS) {
            if (rev->ready) {
                ngx_log_error(NGX_LOG_ALERT, c->log, n,
                              "aio_read() still in progress");
                rev->ready = 0;
            }
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_CRIT, c->log, n, "aio_read() failed");
        rev->error = 1;
        rev->ready = 0;
        return NGX_ERROR;
    }

    n = aio_return(&rev->aiocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "aio_return() failed");

        rev->error = 1;
        rev->ready = 0;
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, rev->log, 0,
                   "aio_read: #%d %d", c->fd, n);

    if (n == 0) {
        rev->eof = 1;
        rev->ready = 0;
    } else {
        rev->ready = 1;
    }

    rev->active = 0;

    return n;
}
