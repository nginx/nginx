
#include <ngx_config.h>
#include <ngx_core.h>


time_t       ngx_cached_time;

ngx_tm_t     ngx_cached_gmtime;

static char  cached_err_log_time[] = "1970/09/28 12:00:00";
ngx_str_t    ngx_cached_err_log_time;

static char  cached_http_time[] = "Mon, 28 Sep 1970 06:00:00 GMT";
ngx_str_t    ngx_cached_http_time;

static char  cached_http_log_time[] = "28/Sep/1970:12:00:00";
ngx_str_t    ngx_cached_http_log_time;


static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fir", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


void ngx_time_init()
{
    struct timeval  tv;

    ngx_memzero(&ngx_cached_gmtime, sizeof(ngx_tm_t));
#ifdef ngx_tm_zone
    ngx_cached_gmtime.ngx_tm_zone = "GMT";
#endif

    ngx_cached_err_log_time.data = cached_err_log_time;
    ngx_cached_http_time.data = cached_http_time;
    ngx_cached_http_log_time.data = cached_http_log_time;

    ngx_gettimeofday(&tv);
    ngx_cached_time = tv.tv_sec;
    ngx_time_update();
}


void ngx_time_update()
{
    ngx_tm_t  tm;

    ngx_gmtime(ngx_cached_time, &ngx_cached_gmtime);

    ngx_cached_http_time.len = ngx_snprintf(ngx_cached_http_time.data,
                                       sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                                       "%s, %02d %s %4d %02d:%02d:%02d GMT",
                                       week[ngx_cached_gmtime.ngx_tm_wday],
                                       ngx_cached_gmtime.ngx_tm_mday,
                                       months[ngx_cached_gmtime.ngx_tm_mon - 1],
                                       ngx_cached_gmtime.ngx_tm_year,
                                       ngx_cached_gmtime.ngx_tm_hour,
                                       ngx_cached_gmtime.ngx_tm_min,
                                       ngx_cached_gmtime.ngx_tm_sec);

    ngx_localtime(&tm);

    ngx_cached_err_log_time.len = ngx_snprintf(ngx_cached_err_log_time.data,
                                       sizeof("1970/09/28 12:00:00"),
                                       "%4d/%02d/%02d %02d:%02d:%02d",
                                       tm.ngx_tm_year, tm.ngx_tm_mon,
                                       tm.ngx_tm_mday, tm.ngx_tm_hour,
                                       tm.ngx_tm_min, tm.ngx_tm_sec);

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


size_t ngx_http_time(char *buf, time_t t)
{
    ngx_tm_t  tm;

    ngx_gmtime(t, &tm);

    return ngx_snprintf(buf, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                                       "%s, %02d %s %4d %02d:%02d:%02d GMT",
                                       week[tm.ngx_tm_wday],
                                       tm.ngx_tm_mday,
                                       months[tm.ngx_tm_mon - 1],
                                       tm.ngx_tm_year,
                                       tm.ngx_tm_hour,
                                       tm.ngx_tm_min,
                                       tm.ngx_tm_sec);
}


void ngx_gmtime(time_t t, ngx_tm_t *tp)
{
    int  sec, min, hour, mday, mon, year, wday, yday, days;

    days = t / 86400;

    /* Jaunary 1, 1970 was Thursday */
    wday = (4 + days) % 7;

    t %= 86400;
    hour = t / 3600;
    t %= 3600;
    min = t / 60; 
    sec = t % 60;

    /* the algorithm based on Gauss's formula */
    
    days = days - (31 + 28) + 719527;

    year = days * 400 / (365 * 400 + 100 - 4 + 1);
    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    mon = (yday + 31) * 12 / 367;
    mday = yday - (mon * 367 / 12 - 31);

    mon += 2;

    if (yday >= 306) {
        yday -= 306;
        year++;
        mon -= 12;

        if (mday == 0) {
            /* Jaunary 31 */
            mon = 1;
            mday = 31;

        } else if (mon == 2) {

            if ((year % 4 == 0) && (year % 100 || (year % 400 == 0))) {
                if (mday > 29) {
                    mon = 3;
                    mday -= 29;
                }

            } else if (mday > 28) {
                mon = 3;
                mday -= 28;
            }
        }

    } else {
        yday += 31 + 28;

        if ((year % 4 == 0) && (year % 100 || (year % 400 == 0))) {
             yday++;
        }
    }

    tp->ngx_tm_sec = sec;
    tp->ngx_tm_min = min;
    tp->ngx_tm_hour = hour;
    tp->ngx_tm_mday = mday;
    tp->ngx_tm_mon = mon;
    tp->ngx_tm_year = year;
    tp->ngx_tm_wday = wday;
}
