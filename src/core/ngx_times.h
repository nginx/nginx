#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


time_t ngx_time();
void ngx_time_update();


extern time_t     ngx_cached_time;
extern ngx_str_t  ngx_cached_http_time;
extern ngx_str_t  ngx_cached_http_log_time;


#endif /* _NGX_TIMES_H_INCLUDED_ */
