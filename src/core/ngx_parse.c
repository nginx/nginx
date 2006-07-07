
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ssize_t
ngx_parse_size(ngx_str_t *line)
{
    u_char     last;
    size_t     len;
    ssize_t    size;
    ngx_int_t  scale;

    len = line->len;
    last = line->data[len - 1];

    switch (last) {
    case 'K':
    case 'k':
        len--;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        scale = 1024 * 1024;
        break;

    default:
        scale = 1;
    }

    size = ngx_atosz(line->data, len);
    if (size == NGX_ERROR) {
        return NGX_ERROR;
    }

    size *= scale;

    return size;
}


off_t
ngx_parse_offset(ngx_str_t *line)
{
    u_char     last;
    off_t      offset;
    size_t     len;
    ngx_int_t  scale;

    len = line->len;
    last = line->data[len - 1];

    switch (last) {
    case 'K':
    case 'k':
        len--;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        scale = 1024 * 1024;
        break;

    case 'G':
    case 'g':
        len--;
        scale = 1024 * 1024 * 1024;
        break;

    default:
        scale = 1;
    }

    offset = ngx_atoof(line->data, len);
    if (offset == NGX_ERROR) {
        return NGX_ERROR;
    }

    offset *= scale;

    return offset;
}


ngx_int_t
ngx_parse_time(ngx_str_t *line, ngx_int_t sec)
{
    size_t       len;
    u_char      *start, last;
    ngx_int_t    value, total, scale;
    ngx_uint_t   max, i;
    enum {
        st_start = 0,
        st_year,
        st_month,
        st_week,
        st_day,
        st_hour,
        st_min,
        st_sec,
        st_msec,
        st_last
    } step;


    start = line->data;
    len = 0;
    total = 0;
    step = sec ? st_start : st_month;

    for (i = 0; /* void */ ; i++) {

        if (i < line->len) {
            if (line->data[i] != ' ') {
                len++;
                continue;
            }

            if (line->data[i] == ' ' && len == 0) {
                start = &line->data[i + 1];
                continue;
            }
        }

        if (len == 0) {
            break;
        }

        last = line->data[i - 1];

        switch (last) {
        case 'y':
            if (step > st_start) {
                return NGX_ERROR;
            }
            step = st_year;
            len--;
            max = 68;
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step > st_year) {
                return NGX_ERROR;
            }
            step = st_month;
            len--;
            max = 828;
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step > st_month) {
                return NGX_ERROR;
            }
            step = st_week;
            len--;
            max = 3550;
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step > st_week) {
                return NGX_ERROR;
            }
            step = st_day;
            len--;
            max = 24855;
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step > st_day) {
                return NGX_ERROR;
            }
            step = st_hour;
            len--;
            max = 596523;
            scale = 60 * 60;
            break;

        case 'm':
            if (step > st_hour) {
                return NGX_ERROR;
            }
            step = st_min;
            len--;
            max = 35791394;
            scale = 60;
            break;

        case 's':
            len--;

            if (line->data[i - 2] == 'm') {
                if (sec || step > st_sec) {
                    return NGX_ERROR;
                }
                step = st_msec;
                len--;
                max = 2147483647;
                scale = 1;
                break;
            }

            if (step > st_min) {
                return NGX_ERROR;
            }

            step = st_sec;
            max = 2147483647;
            scale = 1;
            break;

        default:
            step = st_last;
            max = 2147483647;
            scale = 1;
        }

        value = ngx_atoi(start, len);
        if (value == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (step != st_msec && !sec) {
            scale *= 1000;
            max /= 1000;
        }

        if ((u_int) value > max) {
            return NGX_PARSE_LARGE_TIME;
        }

        total += value * scale;

        if ((u_int) total > 2147483647) {
            return NGX_PARSE_LARGE_TIME;
        }

        if (i >= line->len) {
            break;
        }

        len = 0;
        start = &line->data[i + 1];
    }

    return total;
}
