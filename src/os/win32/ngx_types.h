#ifndef _NGX_TYPES_H_INCLUDED_
#define _NGX_TYPES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef unsigned __int32            u_int32_t;

typedef int                         ssize_t;
typedef long                        time_t;

typedef HANDLE                      ngx_fd_t;
typedef unsigned __int64            off_t;
typedef BY_HANDLE_FILE_INFORMATION  ngx_file_info_t;


#define QD_FMT            "%I64d"
#define QX_FMT            "%I64x"
#define OFF_FMT           "%I64d"
#define PID_FMT           "%d"


#endif /* _NGX_TYPES_H_INCLUDED_ */
