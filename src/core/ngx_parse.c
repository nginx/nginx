
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ssize_t
ngx_parse_size(ngx_str_t *line)
{
    u_char     unit;
    size_t     len;
    ssize_t    size;
    ngx_int_t  scale;

    len = line->len;
    unit = line->data[len - 1];

    switch (unit) {
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
    u_char     unit;
    off_t      offset;
    size_t     len;
    ngx_int_t  scale;

    len = line->len;
    unit = line->data[len - 1];

    switch (unit) {
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
ngx_parse_time(ngx_str_t *line, ngx_uint_t is_sec)
{
    u_char      *p, *last;
    ngx_int_t    value, total, scale;
    ngx_uint_t   max, valid;
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

    valid = 0;
    value = 0;
    total = 0;
    step = is_sec ? st_start : st_month;
    scale = is_sec ? 1 : 1000;

    p = line->data;
    last = p + line->len;

    while (p < last) {

        if (*p >= '0' && *p <= '9') {
            value = value * 10 + (*p++ - '0');
            valid = 1;
            continue;
        }

        switch (*p++) {

        case 'y':
            if (step > st_start) {
                return NGX_ERROR;
            }
            step = st_year;
            max = NGX_MAX_INT32_VALUE / (60 * 60 * 24 * 365);
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step >= st_month) {
                return NGX_ERROR;
            }
            step = st_month;
            max = NGX_MAX_INT32_VALUE / (60 * 60 * 24 * 30);
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step >= st_week) {
                return NGX_ERROR;
            }
            step = st_week;
            max = NGX_MAX_INT32_VALUE / (60 * 60 * 24 * 7);
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step >= st_day) {
                return NGX_ERROR;
            }
            step = st_day;
            max = NGX_MAX_INT32_VALUE / (60 * 60 * 24);
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step >= st_hour) {
                return NGX_ERROR;
            }
            step = st_hour;
            max = NGX_MAX_INT32_VALUE / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (*p == 's') {
                if (is_sec || step >= st_msec) {
                    return NGX_ERROR;
                }
                p++;
                step = st_msec;
                max = NGX_MAX_INT32_VALUE;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return NGX_ERROR;
            }
            step = st_min;
            max = NGX_MAX_INT32_VALUE / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return NGX_ERROR;
            }
            step = st_sec;
            max = NGX_MAX_INT32_VALUE;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return NGX_ERROR;
            }
            step = st_last;
            max = NGX_MAX_INT32_VALUE;
            scale = 1;
            break;

        default:
            return NGX_ERROR;
        }

        if (step != st_msec && !is_sec) {
            scale *= 1000;
            max /= 1000;
        }

        if ((ngx_uint_t) value > max) {
            return NGX_ERROR;
        }

        total += value * scale;

        if ((ngx_uint_t) total > NGX_MAX_INT32_VALUE) {
            return NGX_ERROR;
        }

        value = 0;
        scale = is_sec ? 1 : 1000;

        while (p < last && *p == ' ') {
            p++;
        }
    }

    if (valid) {
        return total + value * scale;
    }

    return NGX_ERROR;
}
