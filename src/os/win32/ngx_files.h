#ifndef _NGX_FILES_H_INCLUDED_
#define _NGX_FILES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* INVALID_FILE_ATTRIBUTES specified but never defined at least in VC6SP2 */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES     0xFFFFFFFF
#endif

#define NGX_INVALID_FILE            INVALID_HANDLE_VALUE
#define NGX_FILE_ERROR              0



#define ngx_open_file(name, access, create)                                 \
            CreateFile(name, access,                                        \
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
            CreateFile(name,                                                \
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

#define ngx_mkdir(name)             CreateDirectory(name, NULL)
#define ngx_mkdir_n                 "CreateDirectory()"

int ngx_file_type(char *filename, ngx_file_info_t *fi);
#define ngx_file_type_n             "GetFileAttributes"

#define ngx_stat_fd(fd, fi)         GetFileInformationByHandle(fd, fi)
#define ngx_stat_fd_n               "GetFileInformationByHandle"

#define ngx_is_dir(fi)      (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
#define ngx_is_file(fi)     !(fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)

#define ngx_file_size(fi)                                                   \
            (((off_t) fi.nFileSizeHigh << 32) | fi.nFileSizeLow)


/* There are 134774 days between 1 Jan 1970 and 1 Jan 1601,
   11644473600 seconds or 11644473600,000,000,0 100-nanosecond intervals */

#define ngx_file_mtime(fi)                                                  \
   (time_t) (((((unsigned __int64) fi.ftLastWriteTime.dwHighDateTime << 32) \
                                 | fi.ftLastWriteTime.dwLowDateTime)        \
                                          - 116444736000000000) / 10000000)


ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset);
#define ngx_read_file_n             "ReadFile()"


#define STDERR_FILENO               (HANDLE) 2


#endif /* _NGX_FILES_H_INCLUDED_ */
