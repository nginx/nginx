#ifndef _NGX_FILES_H_INCLUDED_
#define _NGX_FILES_H_INCLUDED_


#include <ngx_config.h>


/* INVALID_FILE_ATTRIBUTES specified but never defined at least in VC6SP2 */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES  0xFFFFFFFF
#endif

typedef HANDLE                      ngx_fd_t;
#define NGX_INVALID_FILE            INVALID_HANDLE_VALUE
#define NGX_FILE_ERROR              0

typedef unsigned __int64            off_t;

typedef BY_HANDLE_FILE_INFORMATION  ngx_file_info_t;


#define ngx_open_file(name, flags)                                          \
            CreateFile(name, flags,                                         \
                       FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,  \
                       NULL, OPEN_EXISTING, 0, NULL)

#define ngx_open_file_n             "CreateFile()"

#define NGX_FILE_RDONLY             GENERIC_READ

#define ngx_close_file              CloseHandle
#define ngx_close_file_n            "CloseHandle()"

int ngx_file_type(char *filename, ngx_file_info_t *fi);
#define ngx_file_type_n             "GetFileAttributes"

#define ngx_stat_fd(fd, fi)        GetFileInformationByHandle(fd, fi)
#define ngx_stat_fd_n              "GetFileInformationByHandle"

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


#define ngx_read_file_n            "ReadFile()"


#endif /* _NGX_FILES_H_INCLUDED_ */
