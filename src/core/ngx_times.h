#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


void ngx_init_time();
void ngx_time_update();
size_t ngx_http_time(char *buf, time_t t);
void ngx_gmtime(time_t t, ngx_tm_t *tp);

#define ngx_time()   ngx_cached_time


extern time_t     ngx_cached_time;
extern ngx_str_t  ngx_cached_err_log_time;
extern ngx_str_t  ngx_cached_http_time;
extern ngx_str_t  ngx_cached_http_log_time;


#endif /* _NGX_TIMES_H_INCLUDED_ */
