#ifndef _NGX_TYPES_H_INCLUDED_
#define _NGX_TYPES_H_INCLUDED_


#include <ngx_config.h>

#include <sys/types.h>
#include <sys/stat.h>


typedef int          ngx_fd_t;
typedef struct stat  ngx_file_info_t;



#ifdef SOLARIS

#define  QD_FMT   "%lld"
#define  QX_FMT   "%llx"
#define  OFF_FMT  "%lld"

#else

#define  QD_FMT   "%qd"
#define  QX_FMT   "%qx"
#define  OFF_FMT  "%qd"

#endif


#endif /* _NGX_TYPES_H_INCLUDED_ */
