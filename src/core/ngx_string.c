
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


void ngx_encode_base64(ngx_str_t *src, ngx_str_t *dst)
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


ngx_int_t ngx_decode_base64(ngx_str_t *src, ngx_str_t *dst)
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


#if 0
char *ngx_psprintf(ngx_pool_t *p, const char *fmt, ...)
{
    va_list    args;

    va_start(args, fmt);

    while (*fmt) {
         switch(*fmt++) {
         case '%':
             switch(*fmt++) {
             case 's':
                 s = va_arg(args, char *);
                 n += ngx_strlen(s);
                 break;

             default:
                 n++;
         }
         default:
             n++;
         }
    }

    str = ngx_palloc(p, n);

    va_start(args, fmt);

    for (i = 0; i < n; i++) {
         switch(*fmt++) {
         case '%':
             switch(*fmt++) {
             case 's':
                 s = va_arg(args, char *);
                 while (str[i++] = s);
                 break;

             default:
                 n++;
         }
         default:
             str[i] = *fmt;
         }
    }

    len += ngx_vsnprintf(errstr + len, sizeof(errstr) - len - 1, fmt, args);

    va_end(args);

}
#endif
