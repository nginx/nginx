
#include <ngx_config.h>
#include <ngx_core.h>


ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t      n;
    long        high_offset;
    ngx_err_t   err;
    OVERLAPPED  ovlp, *povlp;

    if (ngx_win32_version < NGX_WIN_NT) {
        high_offset = (long) (offset >> 32);
        if (SetFilePointer(file->fd, (long) offset, &high_offset, FILE_BEGIN)
                                                                 == 0xFFFFFFFF)
        {
            err = ngx_errno;
            if (err != NO_ERROR) {
                ngx_log_error(NGX_LOG_ERR, file->log, err,
                              "SeekFilePointer() failed");
                return NGX_ERROR;
            }
        }

        povlp = NULL;

    } else {
        ovlp.Internal = 0;
        ovlp.InternalHigh = 0;
        ovlp.Offset = (DWORD) offset;
        ovlp.OffsetHigh = (DWORD) (offset >> 32);
        ovlp.hEvent = NULL;

        povlp = &ovlp;
    }

    if (ReadFile(file->fd, buf, size, &n, povlp) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "ReadFile() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


/* TODO: as read file */

ssize_t ngx_write_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t n;

    if (WriteFile(file->fd, buf, size, &n, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "WriteFile() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


/* TODO: log error */

int ngx_file_append_mode(ngx_fd_t fd)
{
    if (SetFilePointer(fd, 0, NULL, FILE_END) == 0xFFFFFFFF) {
        if (GetLastError() != NO_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
