
#include <ngx_config.h>
#include <ngx_core.h>


char *ngx_cpystrn(char *dst, char *src, size_t n)
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


int ngx_rstrncmp(char *s1, char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }

    n--;

    for ( ;; ) {
        if (s1[n] != s2[n]) {
            return (u_char) s1[n] - (u_char) s2[n];
        }

        if (n == 0) {
            return 0;
        }

        n--;
    }
}


int ngx_atoi(char *line, size_t n)
{
    int  value;

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


void ngx_md5_text(char *text, u_char *md5)
{
    /* STUB */

    ngx_snprintf(text, 33,
            "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            md5[0], md5[1], md5[2], md5[3], md5[4], md5[5],
            md5[6], md5[7], md5[8], md5[9], md5[10], md5[11],
            md5[12], md5[13], md5[14], md5[15]);
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
