
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hunk.h>
#include <ngx_array.h>
#include <ngx_file.h>
#include <ngx_files.h>


ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    ssize_t n;

    ngx_log_debug(file->log, "read: %x, %d, %qd" _ buf _ size _ offset);

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "pread() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


ssize_t ngx_write_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    ssize_t n;

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

    file->offset += n;

    return n;
}


ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
                                off_t offset, ngx_pool_t *pool)
{
    size_t         size;
    ssize_t        n;
    struct iovec  *iov;
    ngx_err_t      err;
    ngx_array_t    io;

    /* use pwrite() if there's the only hunk in a chain */

    if (ce->next == NULL) {
        return ngx_write_file(file, ce->hunk->pos,
                              ce->hunk->last - ce->hunk->pos, offset);
    }

    ngx_init_array(io, pool, 10, sizeof(struct iovec), NGX_ERROR);
    size = 0;

    while (ce) {
        ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
        iov->iov_base = ce->hunk->pos;
        iov->iov_len = ce->hunk->last - ce->hunk->pos;
        size += ce->hunk->last - ce->hunk->pos;
        ce = ce->next;
    }

    if (lseek(file->fd, offset, SEEK_SET) == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "lseek() failed");
        return NGX_ERROR;
    }

    n = writev(file->fd, (struct iovec *) io.elts, io.nelts);

    ngx_destroy_array(&io);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno, "writev() failed");
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "writev() has written only %d of %d", n, size);
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
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
