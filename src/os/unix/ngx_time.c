
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


void ngx_localtime(ngx_tm_t *tm)
{
#if (HAVE_LOCALTIME_R)
    time_t     now;

    now = ngx_time();
    localtime_r(&now, tm);

#else
    time_t     now;
    ngx_tm_t  *t;

    now = ngx_time();
    t = localtime(&now);
    *tm = *t;

#endif

    tm->ngx_tm_mon++;
    tm->ngx_tm_year += 1900;
}
