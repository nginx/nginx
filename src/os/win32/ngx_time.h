
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_TIME_H_INCLUDED_
#define _NGX_TIME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef uint64_t       ngx_epoch_msec_t;

typedef ngx_int_t      ngx_msec_t;


typedef SYSTEMTIME     ngx_tm_t;
typedef FILETIME       ngx_mtime_t;

#define ngx_tm_sec     wSecond
#define ngx_tm_min     wMinute
#define ngx_tm_hour    wHour
#define ngx_tm_mday    wDay
#define ngx_tm_mon     wMonth
#define ngx_tm_year    wYear
#define ngx_tm_wday    wDayOfWeek

#define ngx_tm_sec_t   u_short
#define ngx_tm_min_t   u_short
#define ngx_tm_hour_t  u_short
#define ngx_tm_mday_t  u_short
#define ngx_tm_mon_t   u_short
#define ngx_tm_year_t  u_short
#define ngx_tm_wday_t  u_short


#define ngx_msleep       Sleep

#define HAVE_GETTIMEZONE  1

ngx_int_t ngx_gettimezone(void);
void ngx_gettimeofday(struct timeval *tp);



#endif /* _NGX_TIME_H_INCLUDED_ */
