
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>


static int mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

time_t ngx_http_parse_time(u_char *value, size_t len)
{
    u_char  *p, *end;
    int      day, month, year, hour, min, sec;
    enum {
        no = 0,
        rfc822,   /* Tue 10 Nov 2002 23:50:13    */
        rfc850,   /* Tuesday, 10-Dec-02 23:50:13 */
        isoc      /* Tue Dec 10 23:50:13 2002    */
    } fmt;

    fmt = 0;
    end = value + len;

#if (NGX_SUPPRESS_WARN)
    day = 32;
    year = 2038;
#endif

    for (p = value; p < end; p++) {
        if (*p == ',') {
            break;
        }

        if (*p == ' ') {
            fmt = isoc;
            break;
        }
    }

    for (p++; p < end; p++)
        if (*p != ' ') {
            break;
        }

    if (end - p < 18) {
        return NGX_ERROR;
        }

    if (fmt != isoc) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
            return NGX_ERROR;
        }

        day = (*p - '0') * 10 + *(p + 1) - '0';
        p += 2;

        if (*p == ' ') {
            if (end - p < 18) {
                return NGX_ERROR;
            }
            fmt = rfc822;

        } else if (*p == '-') {
            fmt = rfc850;

        } else {
            return NGX_ERROR;
        }

        p++;
    }

    switch (*p) {

    case 'J':
        month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
        break;

    case 'F':
        month = 1;
        break;

    case 'M':
        month = *(p + 2) == 'r' ? 2 : 4;
        break;

    case 'A':
        month = *(p + 1) == 'p' ? 3 : 7;
        break;

    case 'S':
        month = 8;
        break;

    case 'O':
        month = 9;
        break;

    case 'N':
        month = 10;
        break;

    case 'D':
        month = 11;
        break;

    default:
        return NGX_ERROR;
    }

    p += 3;

    if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
        return NGX_ERROR;
    }

    p++;

    if (fmt == rfc822) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
            || *(p + 2) < '0' || *(p + 2) > '9'
            || *(p + 3) < '0' || *(p + 3) > '9')
        {
            return NGX_ERROR;
        }

        year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
               + (*(p + 2) - '0') * 10 + *(p + 3) - '0';
        p += 4;

    } else if (fmt == rfc850) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
            return NGX_ERROR;
        }

        year = (*p - '0') * 10 + *(p + 1) - '0';
        year += (year < 70) ? 2000 : 1900;
        p += 2;
    }

    if (fmt == isoc) {
        if (*p == ' ') {
            p++;
        }

        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }

        day = *p++ - '0';

        if (*p != ' ') {
            if (*p < '0' || *p > '9') {
                return NGX_ERROR;
            }

            day = day * 10 + *p++ - '0';
        }

        if (end - p < 14) {
            return NGX_ERROR;
        }
    }

    if (*p++ != ' ') {
        return NGX_ERROR;
    }

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
        return NGX_ERROR;
    }

    hour = (*p - '0') * 10 + *(p + 1) - '0';
    p += 2;

    if (*p++ != ':') {
        return NGX_ERROR;
    }

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
        return NGX_ERROR;
    }

    min = (*p - '0') * 10 + *(p + 1) - '0';
    p += 2;

    if (*p++ != ':') {
        return NGX_ERROR;
    }

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
        return NGX_ERROR;
    }

    sec = (*p - '0') * 10 + *(p + 1) - '0';

    if (fmt == isoc) {
        p += 2;

        if (*p++ != ' ') {
            return NGX_ERROR;
        }

        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
            || *(p + 2) < '0' || *(p + 2) > '9'
            || *(p + 3) < '0' || *(p + 3) > '9')
        {
            return NGX_ERROR;
        }

        year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
               + (*(p + 2) - '0') * 10 + *(p + 3) - '0';
    }

#if 0
    printf("%d.%d.%d %d:%d:%d\n", day, month + 1, year, hour, min, sec);
#endif

    if (hour > 23 || min > 59 || sec > 59) {
         return NGX_ERROR;
    }

    if (day == 29 && month == 1) {
        if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
            return NGX_ERROR;
        }

    } else if (day > mday[month]) {
        return NGX_ERROR;
    }

    if (sizeof(time_t) <= 4 && year >= 2038) {
        return NGX_ERROR;
    }

    /*
     * shift new year to March 1 and start months from 1 (not 0),
     * it's needed for Gauss's formula
     */

    if (--month <= 0) {
       month += 12;
       year -= 1;
    }

           /* Gauss's formula for Grigorian days from 1 March 1 BC */

    return (365 * year + year / 4 - year / 100 + year / 400
            + 367 * month / 12 - 31
            + day

           /*
            * 719527 days were between March 1, 1 BC and March 1, 1970,
            * 31 and 28 days in January and February 1970
            */

            - 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;
}

#if 0
char zero[] = "Sun, 01 Jan 1970 08:49:30";
char one[]  = "Sunday, 11-Dec-02 08:49:30";
char two[]  = "Sun Mar 1 08:49:37 2000";
char thr[]  = "Sun Dec 11 08:49:37 2002";

main()
{
    int rc;

    rc = ngx_http_parse_time(zero, sizeof(zero) - 1);
    printf("rc: %d\n", rc);

    rc = ngx_http_parse_time(one, sizeof(one) - 1);
    printf("rc: %d\n", rc);

    rc = ngx_http_parse_time(two, sizeof(two) - 1);
    printf("rc: %d\n", rc);

    rc = ngx_http_parse_time(thr, sizeof(thr) - 1);
    printf("rc: %d\n", rc);
}

#endif
