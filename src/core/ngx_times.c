
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


/* TODO: remove strftime() */

void ngx_time_update()
{
    ngx_tm_t     *tp, tm;
    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /* STUB: need to move to ngx_init_time() */
    ngx_cached_http_time.data = cached_http_time;
    ngx_cached_http_log_time.data = cached_http_log_time;

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
