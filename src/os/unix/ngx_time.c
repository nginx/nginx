
#include <ngx_config.h>
#include <ngx_core.h>


void ngx_localtime(ngx_tm_t *tm)
{
#if (HAVE_LOCALTIME_R)

    localtime_r((time_t *) &ngx_cached_time, tm);

#else
    ngx_tm_t  *t;

    t = localtime((time_t *) &ngx_cached_time);
    *tm = *t;

#endif

    tm->ngx_tm_mon++;
    tm->ngx_tm_year += 1900;
}
