
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_FILES_H_INCLUDED_
#define _NGX_FILES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* INVALID_FILE_ATTRIBUTES is specified but not defined at least in MSVC6SP2 */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES     0xffffffff
#endif

/* INVALID_SET_FILE_POINTER is not defined at least in MSVC6SP2 */
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER    0xffffffff
#endif


#define NGX_INVALID_FILE            INVALID_HANDLE_VALUE
#define NGX_FILE_ERROR              0



#define ngx_open_file(name, access, create)                                 \
            CreateFile((const char *) name, access,                         \
                       FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,  \
                       NULL, create, FILE_FLAG_BACKUP_SEMANTICS, NULL)
/*
                       NULL, OPEN_EXISTING, 0, NULL)
*/
#define ngx_open_file_n             "CreateFile()"

#define NGX_FILE_RDONLY             GENERIC_READ
#define NGX_FILE_RDWR               GENERIC_READ|GENERIC_WRITE
#define NGX_FILE_CREATE_OR_OPEN     OPEN_ALWAYS
#define NGX_FILE_OPEN               OPEN_EXISTING
#define NGX_FILE_APPEND             0


int ngx_file_append_mode(ngx_fd_t fd);
#define ngx_file_append_mode_n      "SetFilePointer()"


#define ngx_open_tempfile(name, persistent)                                 \
            CreateFile((const char *) name,                                 \
                    GENERIC_READ|GENERIC_WRITE,                             \
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,     \
                    NULL,                                                   \
                    CREATE_NEW,                                             \
                    persistent ? 0:                                         \
                        FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE, \
                    NULL);

#define ngx_open_tempfile_n         "CreateFile()"


#define ngx_close_file              CloseHandle
#define ngx_close_file_n            "CloseHandle()"


#define ngx_delete_file(name)       DeleteFile((const char *) name)
#define ngx_delete_file_n           "DeleteFile()"


#define ngx_rename_file             MoveFile
#define ngx_rename_file_n           "MoveFile()"
int ngx_win32_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_pool_t *pool);


int ngx_file_info(u_char *filename, ngx_file_info_t *fi);
#define ngx_file_info_n             "GetFileAttributesEx()"


#define ngx_fd_info(fd, fi)         GetFileInformationByHandle(fd, fi)
#define ngx_fd_info_n               "GetFileInformationByHandle"


#define ngx_is_dir(fi)      ((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
#define ngx_is_file(fi)     !((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)


#define ngx_file_size(fi)                                                    \
            (((off_t) (fi)->nFileSizeHigh << 32) | (fi)->nFileSizeLow)

#define ngx_file_uniq(fi)   (*(ngx_file_uniq_t *) &(fi)->nFileIndexHigh)


/* 116444736000000000 is commented in src/os/win32/ngx_time.c */

#define ngx_file_mtime(fi)                                                   \
 (time_t) (((((unsigned __int64) (fi)->ftLastWriteTime.dwHighDateTime << 32) \
                               | (fi)->ftLastWriteTime.dwLowDateTime)        \
                                          - 116444736000000000) / 10000000)


#define ngx_getcwd(buf, size)       GetCurrentDirectory(size, buf)
#define ngx_getcwd_n                "GetCurrentDirectory()"
#define NGX_MAX_PATH                MAX_PATH


#define NGX_DIR_MASK                (u_char *) "/*"
#define NGX_DIR_MASK_LEN            2


int ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir);
#define ngx_open_dir_n              "FindFirstFile()"


int ngx_read_dir(ngx_dir_t *dir);
#define ngx_read_dir_n              "FindNextFile()"


#define ngx_close_dir(d)            FindClose((d)->dir)
#define ngx_close_dir_n             "FindClose()"


#define ngx_create_dir(name)        CreateDirectory((const char *) name, NULL)
#define ngx_create_dir_n            "CreateDirectory()"


#define ngx_delete_dir(name)        RemoveDirectory((const char *) name)
#define ngx_delete_dir_n            "RemoveDirectory()"


#define ngx_de_name(dir)            (dir)->fd.cFileName
#define ngx_de_namelen(dir)         ngx_strlen((dir)->fd.cFileName)
#define ngx_de_info(name, dir)      NGX_OK
#define ngx_de_info_n               "dummy()"
#define ngx_de_is_dir(dir)                                                    \
                       ((dir)->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
#define ngx_de_is_file(dir)                                                   \
                       !((dir)->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
#define ngx_de_size(dir)                                                      \
            (((off_t) (dir)->fd.nFileSizeHigh << 32) | (dir)->fd.nFileSizeLow)

/* 116444736000000000 is commented in src/os/win32/ngx_time.c */

#define ngx_de_mtime(dir)                                                     \
             (time_t) (((((unsigned __int64)                                  \
                           (dir)->fd.ftLastWriteTime.dwHighDateTime << 32)    \
                            | (dir)->fd.ftLastWriteTime.dwLowDateTime)        \
                                          - 116444736000000000) / 10000000)



ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset);
#define ngx_read_file_n             "ReadFile()"

ssize_t ngx_write_file(ngx_file_t *file, u_char *buf, size_t size,
                       off_t offset);

ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
                                off_t offset, ngx_pool_t *pool);


#endif /* _NGX_FILES_H_INCLUDED_ */
