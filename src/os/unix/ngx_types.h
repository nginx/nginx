#ifndef _NGX_TYPES_H_INCLUDED_
#define _NGX_TYPES_H_INCLUDED_


#include <ngx_config.h>


typedef int            ngx_fd_t;
typedef struct stat    ngx_file_info_t;
typedef ino_t          ngx_file_uniq_t;

typedef DIR            ngx_dir_t;
typedef struct dirent  ngx_dirent_t;


#endif /* _NGX_TYPES_H_INCLUDED_ */
