
#include <ngx_config.h>
#include <ngx_time.h>

void ngx_localtime(ngx_tm_t *tm)
{
    time_t clock = time(NULL);
    localtime_r(&clock, tm);
    tm->ngx_tm_mon++;
    tm->ngx_tm_year += 1900;
}

u_int ngx_msec(void)
{
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}


#if 0

typedef struct {
    int busy;
    u_int_64 msec;
    time_t sec;
    tm;
    http_time_len;
    http_time[n];
};

volatile *ngx_time_p;

ngx_time()
{
    p = ngx_time_p;
}

ngx_update_time()
{
    u_int64   msec;
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    msec = (unsigned long) tv.tv_sec * 1000 + tv.tv_usec / 1000;
    p = ngx_time_p;

    /* minimum can be for example 0, 10, 50 or 100 ms */
    if (tv_sec > p->sec || msec - p->msec >= minimum) {
        old_p = p;
        /* max_tries < max_slots - 10,
           max_slots should be more than max of threads */
        for (/* void */; i < max_tries; i++) {
            if (++p >= last_slot)
                p = first_slot;

            if (!test_and_set(p->busy)
                break;
        }

        if (i == max_tries) {
            ngx_log_error();
            return;
        }

        if (tv_sec > p->sec) {
            p->sec = tv.tv.sec;
            p->msec = msec;
            localtime_r(&tv.tv_sec, tm);
            make http stirng;

        } else {
            ngx_memcpy(p->sec, old_p->sec, sizeof() - offset_of(, sec));
            p->msec = msec;
        }

        /* here can be too seldom and non-critical race condition */
        if (ngx_time_p == old_p)
            ngx_time_p = p;

        unlock(p->busy);
    }
}

#endif
