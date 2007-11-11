
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    long        high_offset;
    u_long      n;
    ngx_err_t   err;
    OVERLAPPED  ovlp, *povlp;

    if (ngx_win32_version < NGX_WIN_NT) {

        /*
         * under Win9X the overlapped pointer must be NULL
         * so we have to use SetFilePointer() to set the offset
         */

        if (file->offset != offset) {

            /*
             * the maximum file size on the FAT16 is 2G, but on the FAT32
             * the size is 4G so we have to use the high_offset
             * because a single offset is signed value
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
        ovlp.Offset = (u_long) offset;
        ovlp.OffsetHigh = (u_long) (offset >> 32);
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


ssize_t
ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    long        high_offset;
    u_long      n;
    ngx_err_t   err;
    OVERLAPPED  ovlp, *povlp;

    if (ngx_win32_version < NGX_WIN_NT) {

        /*
         * under Win9X the overlapped pointer must be NULL
         * so we have to use SetFilePointer() to set the offset
         */

        if (file->offset != offset) {

            /*
             * the maximum file size on the FAT16 is 2G, but on the FAT32
             * the size is 4G so we have to use high_offset
             * because a single offset is signed value
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
        ovlp.Offset = (u_long) offset;
        ovlp.OffsetHigh = (u_long) (offset >> 32);
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


ssize_t
ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
    ngx_pool_t *pool)
{
    u_char   *buf, *prev;
    size_t    size;
    ssize_t   total, n;

    total = 0;

    while (cl) {
        buf = cl->buf->pos;
        prev = buf;
        size = 0;

        /* coalesce the neighbouring bufs */

        while (cl && prev == cl->buf->pos) {
            size += cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;
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


ngx_int_t
ngx_win32_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_pool_t *pool)
{
    u_char             *name;
    ngx_int_t           rc;
    ngx_uint_t          collision;
    ngx_atomic_uint_t   num;

    name = ngx_palloc(pool, to->len + 1 + 10 + 1 + sizeof("DELETE"));
    if (name == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(name, to->data, to->len);

    collision = 0;

    /* mutex_lock() (per cache or single ?) */

    for ( ;; ) {
        num = ngx_next_temp_number(collision);

        ngx_sprintf(name + to->len, ".%0muA.DELETE", num);

        if (MoveFile((const char *) to->data, (const char *) name) != 0) {
            break;
        }

        collision = 1;

        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno, "MoveFile() failed");
    }

    if (MoveFile((const char *) from->data, (const char *) to->data) == 0) {
        rc = NGX_ERROR;

    } else {
        rc = NGX_OK;
    }

    if (DeleteFile((const char *) name) == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno, "DeleteFile() failed");
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, ngx_errno, "MoveFile() failed");
    }

    /* mutex_unlock() */

    return rc;
}


#if 0

ngx_int_t
ngx_file_info(char *file, ngx_file_info_t *sb)
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

#endif


ngx_int_t
ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s)
{
    uint64_t  intervals;
    FILETIME  ft;

    /* 116444736000000000 is commented in src/os/win32/ngx_time.c */

    intervals = s * 10000000 + 116444736000000000;

    ft.dwLowDateTime = (DWORD) intervals;
    ft.dwHighDateTime = (DWORD) (intervals >> 32);

    if (SetFileTime(fd, NULL, NULL, &ft) != 0) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_file_info(u_char *file, ngx_file_info_t *sb)
{
    /* Win95 */

    sb->dwFileAttributes = GetFileAttributes((const char *) file);

    if (sb->dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
{
    ngx_cpystrn(name->data + name->len, NGX_DIR_MASK, NGX_DIR_MASK_LEN + 1);

    dir->dir = FindFirstFile((const char *) name->data, &dir->finddata);

    if (dir->dir == INVALID_HANDLE_VALUE) {
        return NGX_ERROR;
    }

    dir->valid_info = 1;
    dir->ready = 1;

    return NGX_OK;
}


ngx_int_t
ngx_read_dir(ngx_dir_t *dir)
{
    if (dir->ready) {
        dir->ready = 0;
        return NGX_OK;
    }

    if (FindNextFile(dir->dir, &dir->finddata) != 0) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_open_glob(ngx_glob_t *gl)
{
    u_char  *p;
    size_t   len;

    gl->dir = FindFirstFile((const char *) gl->pattern, &gl->finddata);

    if (gl->dir == INVALID_HANDLE_VALUE) {
        return NGX_ERROR;
    }

    for (p = gl->pattern; *p; p++) {
        if (*p == '/') {
            gl->last = p + 1 - gl->pattern;
        }
    }

    len = ngx_strlen(gl->finddata.cFileName);
    gl->name.len = gl->last + len;

    gl->name.data = ngx_alloc(gl->name.len + 1, gl->log);
    if (gl->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(gl->name.data, gl->pattern, gl->last);
    ngx_cpystrn(gl->name.data + gl->last, (u_char *) gl->finddata.cFileName,
                len + 1);

    gl->ready = 1;

    return NGX_OK;
}


ngx_int_t
ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name)
{
    size_t     len;
    ngx_err_t  err;

    if (gl->ready) {
        *name = gl->name;

        gl->ready = 0;
        return NGX_OK;
    }

    ngx_free(gl->name.data);
    gl->name.data = NULL;

    if (FindNextFile(gl->dir, &gl->finddata) != 0) {

        len = ngx_strlen(gl->finddata.cFileName);
        gl->name.len = gl->last + len;

        gl->name.data = ngx_alloc(gl->name.len + 1, gl->log);
        if (gl->name.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(gl->name.data, gl->pattern, gl->last);
        ngx_cpystrn(gl->name.data + gl->last, (u_char *) gl->finddata.cFileName,
                    len + 1);

        *name = gl->name;

        return NGX_OK;
    }

    err = ngx_errno;

    if (err == NGX_ENOMOREFILES) {
        return NGX_DONE;
    }

    ngx_log_error(NGX_LOG_ALERT, gl->log, err,
                  "FindNextFile(%s) failed", gl->pattern);

    return NGX_ERROR;
}


void
ngx_close_glob(ngx_glob_t *gl)
{
    if (gl->name.data) {
        ngx_free(gl->name.data);
    }

    if (FindClose(gl->dir) == 0) {
        ngx_log_error(NGX_LOG_ALERT, gl->log, ngx_errno,
                      "FindClose(%s) failed", gl->pattern);
    }
}


ngx_int_t
ngx_de_info(u_char *name, ngx_dir_t *dir)
{
    return NGX_OK;
}


ngx_int_t
ngx_de_link_info(u_char *name, ngx_dir_t *dir)
{
    return NGX_OK;
}


ngx_int_t
ngx_file_append_mode(ngx_fd_t fd)
{
#if 0
    if (LockFile(fd, 0, 0, 0xffffffff, 0xffffffff) == 0) {
        return NGX_ERROR;
    }
#endif

    if (SetFilePointer(fd, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
        if (ngx_errno != NO_ERROR) {
            return NGX_ERROR;
        }
    }

#if 0
    if (UnlockFile(fd, 0, 0, 0xffffffff, 0xffffffff) == 0) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}
