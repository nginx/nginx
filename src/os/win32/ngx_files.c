
#include <ngx_config.h>
#include <ngx_core.h>


ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t      n;
    long        high_offset;
    ngx_err_t   err;
    OVERLAPPED  ovlp, *povlp;

    if (ngx_win32_version < NGX_WIN_NT) {

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


ssize_t ngx_write_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t      n;
    long        high_offset;
    ngx_err_t   err;
    OVERLAPPED  ovlp, *povlp;

    if (ngx_win32_version < NGX_WIN_NT) {

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
        ovlp.Internal = 0;
        ovlp.InternalHigh = 0;
        ovlp.Offset = (DWORD) offset;
        ovlp.OffsetHigh = (DWORD) (offset >> 32);
        ovlp.hEvent = NULL;

        povlp = &ovlp;
    }

    if (WriteFile(file->fd, buf, size, &n, povlp) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "WriteFile() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl,
                                off_t offset, ngx_pool_t *pool)
{
    char     *buf, *prev;
    size_t    size;
    ssize_t   total, n;

    total = 0;

    while (cl) {
        buf = cl->hunk->pos;
        prev = buf;
        size = 0;

        /* coalesce the neighbouring hunks */

        while (cl && prev == cl->hunk->pos) {
            size += cl->hunk->last - cl->hunk->pos;
            prev = cl->hunk->last;
            cl = cl->next;
        }

        n = ngx_write_file(file, buf, size, offset);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        total += n;
        offset += n;
    }

    return total;
}


int ngx_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_pool_t *pool)
{
    int         rc, collision;
    u_int       num;
    char       *name;
    ngx_err_t   err;

    name = ngx_palloc(pool, to->len + 1 + 10 + 1 + sizeof("DELETE"));
    ngx_memcpy(name, to->data, to->len);

    collision = 0;

    /* mutex_lock() (per cache or single ?) */

    do {
        num = ngx_next_temp_number(collision);

        ngx_snprintf(name + to->len, 1 + 10 + 1 + sizeof("DELETE"),
                     ".%010u.DELETE", num);

        if (MoveFile(to->data, name) == 0) {
            err = ngx_errno;
            if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
                return NGX_ERROR;
            }

            collision = 1;
            ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno,
                          "MoveFile() failed");
        }

    } while (collision);

    if (ngx_win32_version >= NGX_WIN_NT) {
        if (DeleteFile(name) == 0) {
            ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno,
                          "DeleteFile() failed");
        }
    }

    if (MoveFile(from->data, to->data) == 0) {
        rc = NGX_ERROR;

    } else {
        rc = NGX_OK;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno, "MoveFile() failed");
    }

    /* mutex_unlock() */

    return rc;
}


int ngx_file_type(char *file, ngx_file_info_t *sb)
{
    WIN32_FILE_ATTRIBUTE_DATA  fa;

    /* NT4 and Win98 */

    if (GetFileAttributesEx(file, GetFileExInfoStandard, &fa) == 0) {
        return NGX_ERROR;
    }

    sb->dwFileAttributes = fa.dwFileAttributes;
    sb->ftCreationTime = fa.ftCreationTime;
    sb->ftLastAccessTime = fa.ftLastAccessTime;
    sb->ftLastWriteTime = fa.ftLastWriteTime;
    sb->nFileSizeHigh = fa.nFileSizeHigh;
    sb->nFileSizeLow = fa.nFileSizeLow;

    return NGX_OK;
}


#if 0

/* Win95 */

int ngx_file_type(char *file, ngx_file_info_t *sb)
{
    sb->dwFileAttributes = GetFileAttributes(file);

    if (sb->dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


int ngx_file_append_mode(ngx_fd_t fd)
{
    if (SetFilePointer(fd, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
        if (ngx_errno != NO_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
