
#include <ngx_config.h>
#include <ngx_core.h>


time_t       ngx_cached_time;

static char  cached_http_time[] = "Mon, 28 Sep 1970 06:00:00 GMT";
ngx_str_t    ngx_cached_http_time;

static char  cached_http_log_time[] = "28/Sep/1970:12:00:00";
ngx_str_t    ngx_cached_http_log_time;


time_t ngx_time()
{
    return ngx_cached_time;
}


/* TODO:
 *   cache ngx_tm_t
 *   write own gmtime()
 *   remove strftime()
 *   we can remove localtime_r
 */

void ngx_time_update()
{
    ngx_tm_t     *tp, tm;
    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /* STUB: need to move to ngx_init_time() */
    ngx_cached_http_time.data = cached_http_time;
    ngx_cached_http_log_time.data = cached_http_log_time;

#if 0

    days = sec / 86400;
    days = days - 31 - 28 + 719527;

    year = days * 400 / (365 * 400 + 100 - 4 + 1);
    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    month = (yday + 30) * 12 / 367;
    mday = yday - (month * 367 / 12 - 31);

    if (++month > 11) {
        month -= 12;
        year++;
    }

#endif

    tp = gmtime(&ngx_cached_time);

    ngx_cached_http_time.len = strftime(ngx_cached_http_time.data,
                                        sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                                        "%a, %d %b %Y %H:%M:%S GMT", tp);


    ngx_localtime(&tm);

    ngx_cached_http_log_time.len = ngx_snprintf(ngx_cached_http_log_time.data,
                                       sizeof("28/Sep/1970:12:00:00"),
                                       "%02d/%s/%d:%02d:%02d:%02d",
                                       tm.ngx_tm_mday,
                                       months[tm.ngx_tm_mon - 1],
                                       tm.ngx_tm_year,
                                       tm.ngx_tm_hour,
                                       tm.ngx_tm_min,
                                       tm.ngx_tm_sec);
}
