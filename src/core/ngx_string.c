
#include <ngx_config.h>
#include <ngx_string.h>


char *ngx_cpystrn(char *dst, char *src, size_t n)
{
    if (n == 0)
        return dst;

    for (/* void */; --n; dst++, src++) {
        *dst = *src;

        if (*dst == '\0')
            return dst;
    }

    *dst = '\0';

    return dst;
}
