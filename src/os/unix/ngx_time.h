#ifndef _NGX_TIME_H_INCLUDED_
#define _NGX_TIME_H_INCLUDED_


#include <ngx_config.h>

typedef u_int          ngx_msec_t;

typedef struct tm      ngx_tm_t;

#define ngx_tm_sec     tm_sec
#define ngx_tm_min     tm_min
#define ngx_tm_hour    tm_hour
#define ngx_tm_mday    tm_mday
#define ngx_tm_mon     tm_mon
#define ngx_tm_year    tm_year
#define ngx_tm_wday    tm_wday

#define ngx_msleep(ms) usleep(ms * 1000)

void ngx_localtime(ngx_tm_t *tm);

ngx_msec_t ngx_msec(void);


#endif /* _NGX_TIME_H_INCLUDED_ */
