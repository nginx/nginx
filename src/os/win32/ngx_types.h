#ifndef _NGX_TYPES_H_INCLUDED_
#define _NGX_TYPES_H_INCLUDED_


#include <ngx_config.h>


typedef HANDLE            ngx_file_t;
typedef long              time_t;
typedef unsigned __int64  off_t;


#define QD_FMT            "%I64d"
#define QX_FMT            "%I64x"


#endif /* _NGX_TYPES_H_INCLUDED_ */
