
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_UTF16_BUFLEN  256

static u_short *ngx_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t len);


/* FILE_FLAG_BACKUP_SEMANTICS allows to obtain a handle to a directory */

ngx_fd_t
ngx_open_file(u_char *name, u_long mode, u_long create, u_long access)
{
    u_short   *u;
    ngx_fd_t   fd;
    u_short    utf16[NGX_UTF16_BUFLEN];

    u = ngx_utf8_to_utf16(utf16, name, NGX_UTF16_BUFLEN);

    if (u == NULL) {
        return INVALID_HANDLE_VALUE;
    }

    fd = CreateFileW(u, mode,
                     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                     NULL, create, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (u != utf16) {
        ngx_free(u);
    }

    return fd;
}


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
        err = ngx_errno;

        if (err == ERROR_HANDLE_EOF) {
            return 0;
        }

        ngx_log_error(NGX_LOG_ERR, file->log, err, "ReadFile() failed");
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


ssize_t
ngx_read_fd(ngx_fd_t fd, void *buf, size_t size)
{
    u_long  n;

    if (ReadFile(fd, buf, size, &n, NULL) != 0) {
        return (size_t) n;
    }

    return -1;
}


ssize_t
ngx_write_fd(ngx_fd_t fd, void *buf, size_t size)
{
    u_long  n;

    if (WriteFile(fd, buf, size, &n, NULL) != 0) {
        return (size_t) n;
    }

    return -1;
}


ssize_t
ngx_write_console(ngx_fd_t fd, void *buf, size_t size)
{
    u_long  n;

    (void) CharToOemBuff(buf, buf, size);

    if (WriteFile(fd, buf, size, &n, NULL) != 0) {
        return (size_t) n;
    }

    return -1;
}


ngx_int_t
ngx_win32_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_log_t *log)
{
    u_char             *name;
    ngx_int_t           rc;
    ngx_uint_t          collision;
    ngx_atomic_uint_t   num;

    name = ngx_alloc(to->len + 1 + 10 + 1 + sizeof("DELETE"), log);
    if (name == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(name, to->data, to->len);

    collision = 0;

    /* mutex_lock() (per cache or single ?) */

    for ( ;; ) {
        num = ngx_next_temp_number(collision);

        ngx_sprintf(name + to->len, ".%0muA.DELETE%Z", num);

        if (MoveFile((const char *) to->data, (const char *) name) != 0) {
            break;
        }

        collision = 1;

        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "MoveFile() \"%s\" to \"%s\" failed", to->data, name);
    }

    if (MoveFile((const char *) from->data, (const char *) to->data) == 0) {
        rc = NGX_ERROR;

    } else {
        rc = NGX_OK;
    }

    if (DeleteFile((const char *) name) == 0) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "DeleteFile() \"%s\" failed", name);
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "MoveFile() \"%s\" to \"%s\" failed",
                      from->data, to->data);
    }

    /* mutex_unlock() */

    ngx_free(name);

    return rc;
}


ngx_int_t
ngx_file_info(u_char *file, ngx_file_info_t *sb)
{
    WIN32_FILE_ATTRIBUTE_DATA  fa;

    /* NT4 and Win98 */

    if (GetFileAttributesEx((char *) file, GetFileExInfoStandard, &fa) == 0) {
        return NGX_FILE_ERROR;
    }

    sb->dwFileAttributes = fa.dwFileAttributes;
    sb->ftCreationTime = fa.ftCreationTime;
    sb->ftLastAccessTime = fa.ftLastAccessTime;
    sb->ftLastWriteTime = fa.ftLastWriteTime;
    sb->nFileSizeHigh = fa.nFileSizeHigh;
    sb->nFileSizeLow = fa.nFileSizeLow;

    return ~NGX_FILE_ERROR;
}


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


char *
ngx_realpath(u_char *path, u_char *resolved)
{
    /* STUB */
    return (char *) path;
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
    dir->valid_type = 1;
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
    u_char     *p;
    size_t      len;
    ngx_err_t   err;

    gl->dir = FindFirstFile((const char *) gl->pattern, &gl->finddata);

    if (gl->dir == INVALID_HANDLE_VALUE) {

        err = ngx_errno;

        if ((err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
             && gl->test)
        {
            gl->no_match = 1;
            return NGX_OK;
        }

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

    if (gl->no_match) {
        return NGX_DONE;
    }

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

    if (gl->dir == INVALID_HANDLE_VALUE) {
        return;
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
ngx_directio_on(ngx_fd_t fd)
{
    return 0;
}


ngx_int_t
ngx_directio_off(ngx_fd_t fd)
{
    return 0;
}


size_t
ngx_fs_bsize(u_char *name)
{
    u_char  root[4];
    u_long  sc, bs, nfree, ncl;

    if (name[2] == ':') {
        ngx_cpystrn(root, name, 4);
        name = root;
    }

    if (GetDiskFreeSpace((const char *) name, &sc, &bs, &nfree, &ncl) == 0) {
        return 512;
    }

    return sc * bs;
}


static u_short *
ngx_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t len)
{
    u_char    *p;
    u_short   *u, *last;
    uint32_t   n;

    p = utf8;
    u = utf16;
    last = utf16 + len;

    while (u < last) {

        if (*p < 0x80) {
            *u = (u_short) *p;

            if (*p == 0) {
                return utf16;
            }

            u++;
            p++;

            continue;
        }

        n = ngx_utf8_decode(&p, 4);

        if (n > 0xffff) {
            free(utf16);
            ngx_set_errno(NGX_EILSEQ);
            return NULL;
        }

        *u++ = (u_short) n;
    }

    /* the given buffer is not enough, allocate a new one */

    u = malloc(((p - utf8) + ngx_strlen(p) + 1) * sizeof(u_short));
    if (u == NULL) {
        return NULL;
    }

    ngx_memcpy(u, utf16, len * 2);

    utf16 = u;
    u += len;

    for ( ;; ) {

        if (*p < 0x80) {
            *u = (u_short) *p;

            if (*p == 0) {
                return utf16;
            }

            u++;
            p++;

            continue;
        }

        n = ngx_utf8_decode(&p, 4);

        if (n > 0xffff) {
            free(utf16);
            ngx_set_errno(NGX_EILSEQ);
            return NULL;
        }

        *u++ = (u_short) n;
    }

    /* unreachable */
}
