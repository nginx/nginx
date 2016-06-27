
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * FreeBSD file AIO features and quirks:
 *
 *    if an asked data are already in VM cache, then aio_error() returns 0,
 *    and the data are already copied in buffer;
 *
 *    aio_read() preread in VM cache as minimum 16K (probably BKVASIZE);
 *    the first AIO preload may be up to 128K;
 *
 *    aio_read/aio_error() may return EINPROGRESS for just written data;
 *
 *    kqueue EVFILT_AIO filter is level triggered only: an event repeats
 *    until aio_return() will be called;
 *
 *    aio_cancel() cannot cancel file AIO: it returns AIO_NOTCANCELED always.
 */


extern int  ngx_kqueue;


static ssize_t ngx_file_aio_result(ngx_file_t *file, ngx_event_aio_t *aio,
    ngx_event_t *ev);
static void ngx_file_aio_event_handler(ngx_event_t *ev);


ngx_int_t
ngx_file_aio_init(ngx_file_t *file, ngx_pool_t *pool)
{
    ngx_event_aio_t  *aio;

    aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
    if (aio == NULL) {
        return NGX_ERROR;
    }

    aio->file = file;
    aio->fd = file->fd;
    aio->event.data = aio;
    aio->event.ready = 1;
    aio->event.log = file->log;

    file->aio = aio;

    return NGX_OK;
}


ssize_t
ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    int               n;
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    if (!ngx_file_aio) {
        return ngx_read_file(file, buf, size, offset);
    }

    if (file->aio == NULL && ngx_file_aio_init(file, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->complete = 0;
        ngx_set_errno(aio->err);

        if (aio->err == 0) {
            return aio->nbytes;
        }

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    ngx_memzero(&aio->aiocb, sizeof(struct aiocb));

    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_buf = buf;
    aio->aiocb.aio_nbytes = size;
#if (NGX_HAVE_KQUEUE)
    aio->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
    aio->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    aio->aiocb.aio_sigevent.sigev_value.sigval_ptr = ev;
#endif
    ev->handler = ngx_file_aio_event_handler;

    n = aio_read(&aio->aiocb);

    if (n == -1) {
        n = ngx_errno;

        if (n == NGX_EAGAIN) {
            return ngx_read_file(file, buf, size, offset);
        }

        ngx_log_error(NGX_LOG_CRIT, file->log, n,
                      "aio_read(\"%V\") failed", &file->name);

        if (n == NGX_ENOSYS) {
            ngx_file_aio = 0;
            return ngx_read_file(file, buf, size, offset);
        }

        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio_read: fd:%d %d", file->fd, n);

    ev->active = 1;
    ev->ready = 0;
    ev->complete = 0;

    return ngx_file_aio_result(aio->file, aio, ev);
}


static ssize_t
ngx_file_aio_result(ngx_file_t *file, ngx_event_aio_t *aio, ngx_event_t *ev)
{
    int        n;
    ngx_err_t  err;

    n = aio_error(&aio->aiocb);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio_error: fd:%d %d", file->fd, n);

    if (n == -1) {
        err = ngx_errno;
        aio->err = err;

        ngx_log_error(NGX_LOG_ALERT, file->log, err,
                      "aio_error(\"%V\") failed", &file->name);
        return NGX_ERROR;
    }

    if (n == NGX_EINPROGRESS) {
        if (ev->ready) {
            ev->ready = 0;
            ngx_log_error(NGX_LOG_ALERT, file->log, n,
                          "aio_read(\"%V\") still in progress",
                          &file->name);
        }

        return NGX_AGAIN;
    }

    n = aio_return(&aio->aiocb);

    if (n == -1) {
        err = ngx_errno;
        aio->err = err;
        ev->ready = 1;

        ngx_log_error(NGX_LOG_CRIT, file->log, err,
                      "aio_return(\"%V\") failed", &file->name);
        return NGX_ERROR;
    }

    aio->err = 0;
    aio->nbytes = n;
    ev->ready = 1;
    ev->active = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio_return: fd:%d %d", file->fd, n);

    return n;
}


static void
ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    if (ngx_file_aio_result(aio->file, aio, ev) != NGX_AGAIN) {
        aio->handler(ev);
    }
}
