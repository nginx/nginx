#ifndef _NGX_STAT_H_INCLUDED_
#define _NGX_STAT_H_INCLUDED_


#include <sys/types.h>
#include <sys/stat.h>

typedef struct stat  ngx_stat_t;

#define ngx_is_dir(sb)           (S_ISDIR(sb.st_mode))

#define ngx_stat(file, sb)       stat(file, sb)
#define ngx_stat_n               "stat"

#define ngx_fstat(file, fd, sb)  fstat(fd, sb)
#define ngx_fstat_n              "stat"


#endif /* _NGX_STAT_H_INCLUDED_ */
