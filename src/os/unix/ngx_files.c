
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_file.h>

ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    ssize_t n;

    ngx_log_debug(file->log, "read: %x, %d, %qd" _ buf _ size _ offset);

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "read() failed");
        return NGX_ERROR;
    }

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
