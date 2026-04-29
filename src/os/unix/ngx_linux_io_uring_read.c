/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


extern struct io_uring  *ngx_io_uring_ring;


static void ngx_file_io_uring_event_handler(ngx_event_t *ev);


ngx_int_t
ngx_file_io_uring_init(ngx_file_t *file, ngx_pool_t *pool)
{
    ngx_event_io_uring_t  *io_uring;

    io_uring = ngx_pcalloc(pool, sizeof(ngx_event_io_uring_t));
    if (io_uring == NULL) {
        return NGX_ERROR;
    }

    io_uring->file = file;
    io_uring->fd = file->fd;
    io_uring->event.data = io_uring;
    io_uring->event.ready = 1;
    io_uring->event.log = file->log;

    file->io_uring = io_uring;

    return NGX_OK;
}


ssize_t
ngx_file_io_uring_read(ngx_file_t *file, u_char *buf, size_t size,
    off_t offset, ngx_pool_t *pool)
{
    int                    ret;
    ngx_err_t              err;
    ngx_event_t           *ev;
    ngx_event_io_uring_t  *io_uring;
    struct io_uring_sqe   *sqe;

    if (!ngx_io_uring || ngx_io_uring_ring == NULL) {
        return ngx_read_file(file, buf, size, offset);
    }

    if (file->io_uring == NULL
        && ngx_file_io_uring_init(file, pool) != NGX_OK)
    {
        return NGX_ERROR;
    }

    io_uring = file->io_uring;
    ev = &io_uring->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second io_uring post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "io_uring complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->active = 0;
        ev->complete = 0;

        if (io_uring->res >= 0) {
            ngx_set_errno(0);
            return io_uring->res;
        }

        err = (ngx_err_t) -io_uring->res;
        ngx_set_errno(err);

        ngx_log_error(NGX_LOG_CRIT, file->log, err,
                      "io_uring read \"%s\" failed", file->name.data);

        if (err == NGX_EINVAL || err == NGX_ENOSYS
            || err == NGX_EOPNOTSUPP)
        {
            ngx_io_uring = 0;
            return ngx_read_file(file, buf, size, offset);
        }

        return NGX_ERROR;
    }

    sqe = io_uring_get_sqe(ngx_io_uring_ring);

    if (sqe == NULL) {
        (void) io_uring_submit(ngx_io_uring_ring);
        sqe = io_uring_get_sqe(ngx_io_uring_ring);
    }

    if (sqe == NULL) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "io_uring_get_sqe() failed");
        return ngx_read_file(file, buf, size, offset);
    }

    io_uring_prep_read(sqe, file->fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, ev);

    ev->handler = ngx_file_io_uring_event_handler;

    ret = io_uring_submit(ngx_io_uring_ring);

    if (ret > 0) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    if (ret < 0) {
        err = (ngx_err_t) -ret;

        if (err == NGX_EAGAIN) {
            return ngx_read_file(file, buf, size, offset);
        }

        ngx_log_error(NGX_LOG_CRIT, file->log, err,
                      "io_uring_submit(\"%V\") failed", &file->name);

        if (err == NGX_ENOSYS || err == NGX_EINVAL
            || err == NGX_EOPNOTSUPP)
        {
            ngx_io_uring = 0;
            return ngx_read_file(file, buf, size, offset);
        }

        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                  "io_uring_submit(\"%V\") submitted no requests",
                  &file->name);

    return ngx_read_file(file, buf, size, offset);
}


static void
ngx_file_io_uring_event_handler(ngx_event_t *ev)
{
    ngx_event_io_uring_t  *io_uring;

    io_uring = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "io_uring event handler fd:%d %V",
                   io_uring->fd, &io_uring->file->name);

    io_uring->handler(ev);
}
