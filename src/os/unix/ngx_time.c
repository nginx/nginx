
#include <ngx_config.h>
#include <ngx_time.h>

void ngx_localtime(ngx_tm_t *tm)
{
    time_t clock = time(NULL);
    localtime_r(&clock, tm);
}

u_int ngx_msec(void)
{
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

