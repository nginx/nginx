
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


ngx_int_t ngx_encode_base64(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    u_char         *d, *s;
    ngx_uint_t      i;
    static u_char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (!(d = ngx_palloc(pool, ((src->len + 2) / 3) * 4 + 1))) {
        return NGX_ERROR;
    }

    dst->data = d;
    s = src->data;

    for (i = 0; i < src->len - 2; i += 3) {
        *d++ = basis64[(s[i] >> 2) & 0x3f];
        *d++ = basis64[((s[i] & 3) << 4) | (s[i + 1] >> 4)];
        *d++ = basis64[((s[i + 1] & 0x0f) << 2) | (s[i + 2] >> 6)];
        *d++ = basis64[s[i + 2] & 0x3f];
    }

    if (i < src->len) {
        *d++ = basis64[(s[i] >> 2) & 0x3f];

        if (i == src->len - 1) {
            *d++ = basis64[(s[i] & 3) << 4];
            *d++ = '=';

        } else {
            *d++ = basis64[((s[i] & 3) << 4) | (s[i + 1] >> 4)];
            *d++ = basis64[(s[i + 1] & 0x0f) << 2];
        }

        *d++ = '=';
    }

    dst->len = d - dst->data;
    *d++ = '\0';

    return NGX_OK;
}


ngx_int_t ngx_decode_base64(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    u_char  *d, *s, c;

    if (!(d = ngx_palloc(pool, ((src->len + 3) / 4) * 3))) {
        return NGX_ABORT;
    }

    dst->data = d;
    s = src->data;

    if (*s == '+') {
        c = 62;

    } else if (*s == '/') {
        c = 63;

    } else if (*s >= '0' && *s <= '9') {
        c = *s - '0' + 52;

    } else if (*s >= 'A' && *s <= 'Z') {
        c = *s - 'A';

    } else if (*s >= 'a' && *s <= 'z') {
        c = *s - 'a' + 26;

    } else {
        return NGX_ERROR;
    }

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
