#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <ngx_config.h>


/* INVALID_FILE_ATTRIBUTES specified but never defined at least in VC6SP2 */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES  0xFFFFFFFF
#endif

typedef HANDLE                      ngx_fd_t;
typedef unsigned __int64            off_t;

typedef BY_HANDLE_FILE_INFORMATION  ngx_file_info_t;


#define ngx_open_file(name, flags)                                          \
            CreateFile(name, flags,                                         \
                       FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,  \
                       NULL, OPEN_EXISTING, 0, NULL)

#define ngx_open_file_n             "CreateFile"

#define NGX_FILE_RDONLY          GENERIC_READ


int ngx_file_type(char *filename, ngx_file_info_t *fi);
#define ngx_file_type_n          "GetFileAttributes"

#define ngx_stat_fd(fd, fi)     GetFileInformationByHandle(fd, fi)
#define ngx_stat_fd_n           "GetFileInformationByHandle"

#define ngx_is_dir(fi)          (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)

#define ngx_file_size(fi)                                                   \
            fi.nFileSizeLow

/*
#define ngx_file_size(fi)                                                   \
            ((off_t) fi.nFileSizeHigh << 32 & fi.nFileSizeLow)
*/

#define ngx_file_mtime(fi)       fi.ftLastWriteTime

/*
1970 - 1601:
	116444736000000000
	19DB1DED53E8000
*/


#endif /* _NGX_FILE_H_INCLUDED_ */
