
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


void ngx_time_init(void);
void ngx_time_update(time_t s);
u_char *ngx_http_time(u_char *buf, time_t t);
u_char *ngx_http_cookie_time(u_char *buf, time_t t);
void ngx_gmtime(time_t t, ngx_tm_t *tp);

#if (NGX_THREADS)
ngx_int_t ngx_time_mutex_init(ngx_log_t *log);
#endif

#if (NGX_THREADS && (NGX_TIME_T_SIZE > NGX_SIG_ATOMIC_T_SIZE))

#define ngx_time()        *ngx_cached_time
extern volatile time_t    *ngx_cached_time;

#else

#define ngx_time()         ngx_cached_time
extern volatile time_t     ngx_cached_time;

#endif


extern ngx_thread_volatile ngx_str_t  ngx_cached_err_log_time;
extern ngx_thread_volatile ngx_str_t  ngx_cached_http_time;
extern ngx_thread_volatile ngx_str_t  ngx_cached_http_log_time;

extern ngx_int_t   ngx_gmtoff;

/*
 * milliseconds elapsed since epoch and truncated to ngx_msec_t,
 * used in event timers
 */
extern ngx_msec_t  ngx_current_time;


#endif /* _NGX_TIMES_H_INCLUDED_ */
