
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


void ngx_localtime(ngx_tm_t *tm)
{
#if (NGX_HAVE_LOCALTIME_R)
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


void ngx_libc_localtime(struct tm *tm)
{
#if (NGX_HAVE_LOCALTIME_R)
    time_t      now;

    now = ngx_time();
    localtime_r(&now, tm);

#else
    time_t      now;
    struct tm  *t;

    now = ngx_time();
    t = localtime(&now);
    *tm = *t;

#endif
}


void ngx_libc_gmtime(struct tm *tm)
{
#if (NGX_HAVE_LOCALTIME_R)
    time_t      now;

    now = ngx_time();
    gmtime_r(&now, tm);

#else
    time_t      now;
    struct tm  *t;

    now = ngx_time();
    t = gmtime(&now);
    *tm = *t;

#endif
}
