
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t n;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "read: %d, %X, %d, " OFF_T_FMT, file->fd, buf, size, offset);

#if (HAVE_PREAD)

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "pread() failed, file \"%s\"", file->name.data);
        return NGX_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "lseek() failed");
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    n = read(file->fd, buf, size);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "read() failed");
        return NGX_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


ssize_t ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t n;

#if (HAVE_PWRITE)

    n = pwrite(file->fd, buf, size, offset);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "pwrite() failed");
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "pwrite() has written only %d of %d", n, size);
        return NGX_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "lseek() failed");
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    n = write(file->fd, buf, size);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "write() failed");
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "write() has written only %d of %d", n, size);
        return NGX_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


int ngx_open_tempfile(u_char *name, ngx_uint_t persistent)
{
    ngx_fd_t  fd;

    fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR, 0600);

    if (fd != -1 && !persistent) {
        unlink((const char *) name);
    }

    return fd;
}


ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl,
                                off_t offset, ngx_pool_t *pool)
{
    u_char        *prev;
    size_t         size;
    ssize_t        n;
    struct iovec  *iov;
    ngx_err_t      err;
    ngx_array_t    io;

    /* use pwrite() if there's the only buf in a chain */

    if (cl->next == NULL) {
        return ngx_write_file(file, cl->buf->pos,
                              (size_t) (cl->buf->last - cl->buf->pos),
                              offset);
    }

    prev = NULL;
    iov = NULL;
    size = 0;

    ngx_init_array(io, pool, 10, sizeof(struct iovec), NGX_ERROR);

    /* create the iovec and coalesce the neighbouring bufs */

    while (cl) {
        if (prev == cl->buf->pos) {
            iov->iov_len += cl->buf->last - cl->buf->pos;

        } else {
            ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
            iov->iov_base = (void *) cl->buf->pos;
            iov->iov_len = cl->buf->last - cl->buf->pos;
        }

        size += cl->buf->last - cl->buf->pos;
        prev = cl->buf->last;
        cl = cl->next;
    }

    /* use pwrite() if there's the only iovec buffer */

    if (io.nelts == 1) {
        iov = io.elts;
        return ngx_write_file(file, (u_char *) iov[0].iov_base, iov[0].iov_len,
                              offset);
    }

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "lseek() failed");
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    n = writev(file->fd, io.elts, io.nelts);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "writev() failed");
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "writev() has written only %d of %d", n, size);
        return NGX_ERROR;
    }

    file->sys_offset += n;
    file->offset += n;

    return n;
}


int ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
{
    dir->dir = opendir((const char *) name->data);

    if (dir->dir == NULL) {
        return NGX_ERROR;
    }

    dir->info_valid = 0;

    return NGX_OK;
}


#if 0

ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    if (!file->read->ready) {

        ngx_memzero(&file->iocb, sizeof(iocb));
        file->iocb.aio_fildes = file->fd;
        file->iocb.aio_buf = buf;
        file->iocb.aio_nbytes = size;
        file->iocb.aio_offset = offset;
#if (USE_AIO_KQUEUE)
        file->iocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        file->iocb.aio_sigevent.sigev_notify_kqueue = tid->kq;
        file->iocb.aio_sigevent.sigev_value = (union sigval) file;
#endif
#if (USE_AIO_SIGNAL)
        file->iocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
        file->iocb.aio_sigevent.sigev_signo = NGX_SIGAIO;
#ifndef __FreeBSD__
        file->iocb.aio_sigevent.sigev_value.sival_ptr = file;
#endif
#endif

        if (aio_read(&file->iocb) == -1) {
            ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                          "aio_read() failed");
            return NGX_ERROR;

        n = aio_error(&file->iocb);
        if (n == EINPROGRESS)
            return NGX_AGAIN;

        if (n == -1) {
            ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                          "aio_read() failed");
            return NGX_ERROR;
        }
    }

    ngx_assert(file->iocb.aio_buf == buf), return NGX_ERROR,
               "ngx_aio_read_file: another buffer is passed");

    n = aio_return(&file->iocb);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                      "aio_read() failed");
        return NGX_ERROR;
    }

    return n;
}

#endif
