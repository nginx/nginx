
#include <ngx_config.h>
#include <ngx_core.h>


ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t      n;
    OVERLAPPED  ovlp, *povlp;

#if (WIN9X)

    if (ngx_win32_version < NGX_WIN_NT) {
        long        high_offset;
        ngx_err_t   err;

        /*
         * in Win9X the overlapped pointer must be NULL
         * so we need to use SetFilePointer() to set the offset
         */

        if (file->offset != offset) {

            /*
             * the maximum file size on FAT16 is 2G, but on FAT32 it's 4G so we
             * need to use high_offset because a single offset is signed value
             */

            high_offset = (long) (offset >> 32);
            if (SetFilePointer(file->fd, (long) offset, &high_offset,
                               FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            {
                /*
                 * INVALID_SET_FILE_POINTER is 0xffffffff and it can be valid
                 * value for large file so we need also to check GetLastError()
                 */

                err = ngx_errno;
                if (err != NO_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, file->log, err,
                                  "SeekFilePointer() failed");
                    return NGX_ERROR;
                }
            }
        }

        povlp = NULL;

    } else {

#endif
        ovlp.Internal = 0;
        ovlp.InternalHigh = 0;
        ovlp.Offset = (DWORD) offset;
        ovlp.OffsetHigh = (DWORD) (offset >> 32);
        ovlp.hEvent = NULL;

        povlp = &ovlp;

#if (WIN9X)
    }
#endif

    if (ReadFile(file->fd, buf, size, &n, povlp) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "ReadFile() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


ssize_t ngx_write_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t      n;
    OVERLAPPED  ovlp, *povlp;

#if (WIN9X)

    if (ngx_win32_version < NGX_WIN_NT) {
        long        high_offset;
        ngx_err_t   err;

        /*
         * in Win9X the overlapped pointer must be NULL
         * so we need to use SetFilePointer() to set the offset
         */

        if (file->offset != offset) {

            /*
             * the maximum file size on FAT16 is 2G, but on FAT32 it's 4G so we
             * need to use high_offset because a single offset is signed value
             */

            high_offset = (long) (offset >> 32);
            if (SetFilePointer(file->fd, (long) offset, &high_offset,
                               FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            {
                /*
                 * INVALID_SET_FILE_POINTER is 0xffffffff and it can be valid
                 * value for large file so we need also to check GetLastError()
                 */

                err = ngx_errno;
                if (err != NO_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, file->log, err,
                                  "SeekFilePointer() failed");
                    return NGX_ERROR;
                }
            }
        }

        povlp = NULL;

    } else {

#endif

        ovlp.Internal = 0;
        ovlp.InternalHigh = 0;
        ovlp.Offset = (DWORD) offset;
        ovlp.OffsetHigh = (DWORD) (offset >> 32);
        ovlp.hEvent = NULL;

        povlp = &ovlp;

#if (WIN9X)
    }
#endif

    if (WriteFile(file->fd, buf, size, &n, povlp) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "WriteFile() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


int ngx_file_append_mode(ngx_fd_t fd)
{
    ngx_err_t  err;

    if (SetFilePointer(fd, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
        err = ngx_errno;
        if (err != NO_ERROR) {
            ngx_log_error(NGX_LOG_ERR, file->log, err,
                          "SeekFilePointer() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
