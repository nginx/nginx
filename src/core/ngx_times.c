
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_epoch_msec_t  ngx_elapsed_msec;
ngx_epoch_msec_t  ngx_old_elapsed_msec;
ngx_epoch_msec_t  ngx_start_msec;

static ngx_tm_t   ngx_cached_gmtime;
static ngx_int_t  ngx_gmtoff;


/*
 * In the threaded mode only one thread updates the cached time and strings
 * and these operations are protected by the mutex.  The reading of the cached
 * time and strings is not protected by the mutex.  To avoid the race
 * conditions for non-atomic values we use the NGX_TIME_SLOTS slots to store
 * time value and strings.  Thus thread may get the corrupted values only
 * if it is preempted while copying and then it is not scheduled to run
 * more than NGX_TIME_SLOTS seconds.
 */

#if (NGX_THREADS)

#define NGX_TIME_SLOTS  60
static ngx_uint_t       slot = NGX_TIME_SLOTS;

static ngx_mutex_t     *ngx_time_mutex;

#else

#define NGX_TIME_SLOTS  1
#define slot            0

#endif


#if (NGX_THREADS && (TIME_T_SIZE > SIG_ATOMIC_T_SIZE))

volatile time_t  *ngx_cached_time;
static time_t     cached_time[NGX_TIME_SLOTS];

#else

volatile time_t   ngx_cached_time;

#endif


ngx_thread_volatile ngx_str_t  ngx_cached_err_log_time;
ngx_thread_volatile ngx_str_t  ngx_cached_http_time;
ngx_thread_volatile ngx_str_t  ngx_cached_http_log_time;


static u_char  cached_err_log_time[NGX_TIME_SLOTS]
                                               [sizeof("1970/09/28 12:00:00")];
static u_char  cached_http_time[NGX_TIME_SLOTS]
                                     [sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
static u_char  cached_http_log_time[NGX_TIME_SLOTS]
                                        [sizeof("28/Sep/1970:12:00:00 +0600")];


static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


void ngx_time_init()
{
    struct timeval  tv;

    ngx_memzero(&ngx_cached_gmtime, sizeof(ngx_tm_t));
#ifdef ngx_tm_zone
    ngx_cached_gmtime.ngx_tm_zone = "GMT";
#endif

    ngx_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1;
    ngx_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    ngx_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;

#if (NGX_THREADS && (TIME_T_SIZE > SIG_ATOMIC_T_SIZE))
    ngx_cached_time = &cached_time[0];
#endif

    ngx_gettimeofday(&tv);

    ngx_start_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000 + tv.tv_usec / 1000;
    ngx_old_elapsed_msec = 0;
    ngx_elapsed_msec = 0;

#if !(WIN32)
    tzset();
#endif

    ngx_time_update(tv.tv_sec);
}


#if (NGX_THREADS)

ngx_int_t ngx_time_mutex_init(ngx_log_t *log)
{
    if (!(ngx_time_mutex = ngx_mutex_init(log, NGX_MUTEX_LIGHT))) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


void ngx_time_update(time_t s)
{
    u_char    *p;
    ngx_tm_t   tm;

    if (ngx_time() == s) {
        return;
    }

#if (NGX_THREADS)

    if (ngx_mutex_trylock(ngx_time_mutex) != NGX_OK) {
        return;
    }

    if (slot == NGX_TIME_SLOTS) {
        slot = 0;
    } else {
        slot++;
    }

#if (NGX_THREADS && (TIME_T_SIZE > SIG_ATOMIC_T_SIZE))
    ngx_cached_time = &cached_time[slot];
#endif

#endif

    ngx_time() = s;

    ngx_gmtime(s, &ngx_cached_gmtime);


    p = cached_http_time[slot];

    ngx_snprintf((char *) p, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                 "%s, %02d %s %4d %02d:%02d:%02d GMT",
                 week[ngx_cached_gmtime.ngx_tm_wday],
                 ngx_cached_gmtime.ngx_tm_mday,
                 months[ngx_cached_gmtime.ngx_tm_mon - 1],
                 ngx_cached_gmtime.ngx_tm_year,
                 ngx_cached_gmtime.ngx_tm_hour,
                 ngx_cached_gmtime.ngx_tm_min,
                 ngx_cached_gmtime.ngx_tm_sec);

    ngx_cached_http_time.data = p;


#if (HAVE_GETTIMEZONE)

    ngx_gmtoff = ngx_gettimezone();
    ngx_gmtime(s + ngx_gmtoff * 60, &tm);

#elif (HAVE_GMTOFF)

    ngx_localtime(&tm);
    ngx_gmtoff = tm.ngx_tm_gmtoff / 60;

#else

    ngx_localtime(&tm);
    ngx_gmtoff = ngx_timezone(tm.ngx_tm_isdst);

#endif


    p = cached_err_log_time[slot];

    ngx_snprintf((char *) p, sizeof("1970/09/28 12:00:00"),
                 "%4d/%02d/%02d %02d:%02d:%02d",
                 tm.ngx_tm_year, tm.ngx_tm_mon,
                 tm.ngx_tm_mday, tm.ngx_tm_hour,
                 tm.ngx_tm_min, tm.ngx_tm_sec);

    ngx_cached_err_log_time.data = p;


    p = cached_http_log_time[slot];

    ngx_snprintf((char *) p, sizeof("28/Sep/1970:12:00:00 +0600"),
                 "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d",
                 tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                 tm.ngx_tm_year, tm.ngx_tm_hour,
                 tm.ngx_tm_min, tm.ngx_tm_sec,
                 ngx_gmtoff < 0 ? '-' : '+',
                 abs(ngx_gmtoff / 60), abs(ngx_gmtoff % 60));

    ngx_cached_http_log_time.data = p;


#if (NGX_THREADS)
    ngx_mutex_unlock(ngx_time_mutex);
#endif

}


size_t ngx_http_time(u_char *buf, time_t t)
{
    ngx_tm_t  tm;

    ngx_gmtime(t, &tm);

    return ngx_snprintf((char *) buf, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                                      "%s, %02d %s %4d %02d:%02d:%02d GMT",
                                      week[tm.ngx_tm_wday],
                                      tm.ngx_tm_mday,
                                      months[tm.ngx_tm_mon - 1],
                                      tm.ngx_tm_year,
                                      tm.ngx_tm_hour,
                                      tm.ngx_tm_min,
                                      tm.ngx_tm_sec);
}


size_t ngx_http_cookie_time(u_char *buf, time_t t)
{
    ngx_tm_t  tm;

    ngx_gmtime(t, &tm);

    /*
     * Netscape 3.x does not understand 4-digit years at all and
     * 2-digit years more than "37"
     */

    if (tm.ngx_tm_year > 2037) {
        return ngx_snprintf((char *) buf,
                                      sizeof("Mon, 28-Sep-1970 06:00:00 GMT"),
                                      "%s, %02d-%s-%d %02d:%02d:%02d GMT",
                                      week[tm.ngx_tm_wday],
                                      tm.ngx_tm_mday,
                                      months[tm.ngx_tm_mon - 1],
                                      tm.ngx_tm_year,
                                      tm.ngx_tm_hour,
                                      tm.ngx_tm_min,
                                      tm.ngx_tm_sec);
    } else {
        return ngx_snprintf((char *) buf,
                                      sizeof("Mon, 28-Sep-70 06:00:00 GMT"),
                                      "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
                                      week[tm.ngx_tm_wday],
                                      tm.ngx_tm_mday,
                                      months[tm.ngx_tm_mon - 1],
                                      tm.ngx_tm_year % 100,
                                      tm.ngx_tm_hour,
                                      tm.ngx_tm_min,
                                      tm.ngx_tm_sec);
    }
}


void ngx_gmtime(time_t t, ngx_tm_t *tp)
{
    ngx_int_t  sec, min, hour, mday, mon, year, wday, yday, days;

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

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         */

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

/*
 *  there is no "yday" in Win32 SYSTEMTIME
 *
 *  } else {
 *      yday += 31 + 28;
 *
 *      if ((year % 4 == 0) && (year % 100 || (year % 400 == 0))) {
 *           yday++;
 *      }
 */
    }

    tp->ngx_tm_sec = (ngx_tm_sec_t) sec;
    tp->ngx_tm_min = (ngx_tm_min_t) min;
    tp->ngx_tm_hour = (ngx_tm_hour_t) hour;
    tp->ngx_tm_mday = (ngx_tm_mday_t) mday;
    tp->ngx_tm_mon = (ngx_tm_mon_t) mon;
    tp->ngx_tm_year = (ngx_tm_year_t) year;
    tp->ngx_tm_wday = (ngx_tm_wday_t) wday;
}
