
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    for (/* void */; --n; dst++, src++) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }
    }

    *dst = '\0';

    return dst;
}


/*
 * supported formats:
 *    %[0][width]O     off_t
 *    %[0][width]T     time_t
 *    %[0][width]S     ssize_t
 *    %[0][width]uS    size_t
 *    %[0][width]uxS   size_t in hex
 *    %[0][width]l     long
 *    %[0][width]d     int
 *    %[0][width]i     ngx_int_t
 *    %[0][width]ui    ngx_uint_t
 *    %[0][width]uxi   ngx_uint_t in hex
 *    %s               null-terminated string
 *    %%               %
 *
 */

u_char *ngx_sprintf(u_char *buf, char *fmt, ...)
{
    u_char        *p, c, temp[NGX_MAX_INT_LEN];
    int            d;
    long           l;
    off_t          offset;
    size_t         size, len;
    ssize_t        ssize;
    time_t         sec;
    va_list        arg;
    ngx_int_t      i;
    ngx_uint_t     ui, zero, width, sign, hexadecimal;
    static u_char  hex[] = "0123456789abcdef";

    va_start(arg, fmt);

    while (*fmt) {
        if (*fmt == '%') {

            zero = (*++fmt == '0') ? 1 : 0;
            width = 0;
            sign = 1;
            hexadecimal = 0;

            p = temp + NGX_MAX_INT_LEN;

            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + *fmt++ - '0';
            }


            for ( ;; ) {
                switch (*fmt) {

                case 'u':
                    sign = 0;
                    fmt++;
                    continue;

                case 'x':
                    hexadecimal = 1;
                    fmt++;
                    continue;

                default:
                    break;
                }

                break;
            }


            switch (*fmt) {

            case 'O':
                offset = va_arg(arg, off_t);

                if (offset < 0) {
                    *buf++ = '-';
                    offset = -offset;
                }

                do {
                    *--p = (u_char) (offset % 10 + '0');
                } while (offset /= 10);

                break;

            case 'T':
                sec = va_arg(arg, time_t);

                if (sec < 0) {
                    *buf++ = '-';
                    sec = -sec;
                }

                do {
                    *--p = (u_char) (sec % 10 + '0');
                } while (sec /= 10);

                break;

            case 'S':
                if (sign) {
                    ssize = va_arg(arg, ssize_t);

                    if (ssize < 0) {
                        *buf++ = '-';
                        size = (size_t) -ssize;

                    } else {
                        size = (size_t) ssize;
                    }

                } else {
                    size = va_arg(arg, size_t);
                }

                if (hexadecimal) {
                    do {
                        *--p = hex[size & 0xf];
                    } while (size >>= 4);

                } else {
                    do {
                        *--p = (u_char) (size % 10 + '0');
                    } while (size /= 10);
                }

                break;

            case 'l':
                l = va_arg(arg, long);

                if (l < 0) {
                    *buf++ = '-';
                    l = -l;
                }

                do {
                    *--p = (u_char) (l % 10 + '0');
                } while (l /= 10);

                break;

            case 'd':
                d = va_arg(arg, int);

                if (d < 0) {
                    *buf++ = '-';
                    d = -d;
                }

                do {
                    *--p = (u_char) (d % 10 + '0');
                } while (d /= 10);

                break;

            case 'i':
                if (sign) {
                    i = va_arg(arg, ngx_int_t);

                    if (i < 0) {
                        *buf++ = '-';
                        ui = (ngx_uint_t) -i;

                    } else {
                        ui = (ngx_uint_t) i;
                    }

                } else {
                    ui = va_arg(arg, ngx_uint_t);
                }

                if (hexadecimal) {
                    do {
                        *--p = hex[ui & 0xf];
                    } while (ui >>= 4);

                } else {
                    do {
                        *--p = (u_char) (ui % 10 + '0');
                    } while (ui /= 10);
                }

                break;

            case 's':
                p = va_arg(arg, u_char *);

                while (*p) {
                    *buf++ = *p++;
                }
                fmt++;

                continue;

            case '%':
                *buf++ = '%';
                fmt++;

                continue;

            default:
                *buf++ = *fmt++;

                continue;
            }

            len = (temp + NGX_MAX_INT_LEN) - p;

            c = (u_char) (zero ? '0' : ' ');

            while (len++ < width) {
                *buf++ = c;
            }

            buf = ngx_cpymem(buf, p, ((temp + NGX_MAX_INT_LEN) - p));

            fmt++;

        } else {
            *buf++ = *fmt++;
        }
    }

    va_end(arg);

    *buf = '\0';

    return buf;
}


ngx_int_t ngx_rstrncmp(u_char *s1, u_char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }

    n--;

    for ( ;; ) {
        if (s1[n] != s2[n]) {
            return s1[n] - s2[n];
        }

        if (n == 0) {
            return 0;
        }

        n--;
    }
}


ngx_int_t ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n)
{
    u_char  c1, c2;

    if (n == 0) {
        return 0;
    }

    n--;

    for ( ;; ) {
        c1 = s1[n];
        if (c1 >= 'a' && c1 <= 'z') {
            c1 -= 'a' - 'A';
        }

        c2 = s2[n];
        if (c2 >= 'a' && c2 <= 'z') {
            c2 -= 'a' - 'A';
        }

        if (c1 != c2) {
            return c1 - c2;
        }

        if (n == 0) {
            return 0;
        }

        n--;
    }
}


ngx_int_t ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


ngx_int_t ngx_hextoi(u_char *line, size_t n)
{
    u_char     ch;
    ngx_int_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        ch = *line;

        if (ch >= '0' && ch <= '9') {
            value = value * 16 + (ch - '0');
            continue;
        }

        if (ch >= 'A' && ch <= 'F') {
            value = value * 16 + (ch - 'A' + 10);
            continue;
        }

        if (ch >= 'a' && ch <= 'f') {
            value = value * 16 + (ch - 'a' + 10);
            continue;
        }

        return NGX_ERROR;
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


void ngx_md5_text(u_char *text, u_char *md5)
{
    int            i;
    static u_char  hex[] = "0123456789abcdef";

    for (i = 0; i < 16; i++) {
        *text++ = hex[md5[i] >> 4];
        *text++ = hex[md5[i] & 0xf];
    }

    *text = '\0';
}


void ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    u_char         *d, *s;
    size_t          len;
    static u_char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    len = src->len;
    s = src->data;
    d = dst->data;

    while (len > 2) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];
        *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis64[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis64[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis64[(s[0] & 3) << 4];
            *d++ = '=';

        } else {
            *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis64[(s[1] & 0x0f) << 2];
        }

        *d++ = '=';
    }

    dst->len = d - dst->data;
}


ngx_int_t ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    size_t          len;
    u_char         *d, *s;
    static u_char   basis64[] =
        { 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
          52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
          77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
          15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
          77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
          41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77 };

    for (len = 0; len < src->len; len++) {
        if (src->data[len] == '=') {
            break;
        }

        if (basis64[src->data[len]] == 77) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    s = src->data;
    d = dst->data;

    while (len > 3) {
        *d++ = (u_char) (basis64[s[0]] << 2 | basis64[s[1]] >> 4);
        *d++ = (u_char) (basis64[s[1]] << 4 | basis64[s[2]] >> 2);
        *d++ = (u_char) (basis64[s[2]] << 6 | basis64[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis64[s[0]] << 2 | basis64[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis64[s[1]] << 4 | basis64[s[2]] >> 2);
    }

    dst->len = d - dst->data;

    return NGX_OK;
}


ngx_int_t ngx_escape_uri(u_char *dst, u_char *src, size_t size)
{
    ngx_int_t         n;
    ngx_uint_t        i;
    static u_char     hex[] = "0123456789abcdef";
    static uint32_t   escape[] =
        { 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                      /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
          0x80000021, /* 1000 0000 0000 0000  0000 0000 0010 0001 */

                      /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
          0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                      /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
          0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */ };

    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n  = 0;

        for (i = 0; i < size; i++) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }
            src++;
        }

        return n;
    }

    for (i = 0; i < size; i++) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
    }

    return NGX_OK;
}
