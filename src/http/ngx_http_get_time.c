
#include <nginx.h>

#include <ngx_config.h>


ngx_http_get_time(char *buf, time_t t)
{
    struct tm *tp;

    tp = gmtime(&t);
    return strftime(buf, 30, "%a, %d %b %Y %H:%M:%S GMT", tp);
}
