#ifndef _NGX_TIME_H_INCLUDED_
#define _NGX_TIME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef uint64_t       ngx_epoch_msec_t;

typedef ngx_int_t      ngx_msec_t;
#define NGX_MAX_MSEC   (ngx_msec_t) -1

typedef struct tm      ngx_tm_t;

#define ngx_tm_sec     tm_sec
#define ngx_tm_min     tm_min
#define ngx_tm_hour    tm_hour
#define ngx_tm_mday    tm_mday
#define ngx_tm_mon     tm_mon
#define ngx_tm_year    tm_year
#define ngx_tm_wday    tm_wday

#ifndef SOLARIS
#define ngx_tm_zone    tm_zone
#endif

#define ngx_tm_sec_t   int
#define ngx_tm_min_t   int
#define ngx_tm_hour_t  int
#define ngx_tm_mday_t  int
#define ngx_tm_mon_t   int
#define ngx_tm_year_t  int
#define ngx_tm_wday_t  int



void ngx_localtime(ngx_tm_t *tm);

#define ngx_gettimeofday(tp)  gettimeofday(tp, NULL);
#define ngx_msleep(ms)        usleep(ms * 1000)


extern time_t  ngx_cached_time;


#endif /* _NGX_TIME_H_INCLUDED_ */
