#ifndef _NGX_STAT_H_INCLUDED_
#define _NGX_STAT_H_INCLUDED_


#include <windows.h>

/* INVALID_FILE_ATTRIBUTES specified but never defined */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES  0xFFFFFFFF
#endif

typedef DWORD  ngx_stat_t;


#define ngx_is_dir(sb)           (*sb & FILE_ATTRIBUTE_DIRECTORY) 

#define ngx_stat_n               "GetFileAttributes"

#define ngx_fstat(file, fd, sb)  ngx_stat(file, sb)
#define ngx_fstat_n              "GetFileAttributes"


int ngx_stat(char *file, ngx_stat_t *sb);


#endif /* _NGX_STAT_H_INCLUDED_ */
