
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_alloc.h>
#include <ngx_time.h>
#include <ngx_http.h>


ngx_http_module_t  ngx_http_log_module;


static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


int ngx_http_log_handler(ngx_http_request_t *r)
{
    size_t    len;
    char     *line, *p;
    ngx_tm_t  tm;

#if (WIN32)
    len = 2 + 22 + 3 + 20 + 5 + 20 + 2;
#else
    len = 2 + 22 + 3 + 20 + 5 + 20 + 1;
#endif

    len += r->connection->addr_text.len;
    len += r->request_line.len;


    ngx_test_null(line, ngx_palloc(r->pool, len), NGX_ERROR);
    p = line;

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);
    p += r->connection->addr_text.len;

    *p++ = ' ';

    ngx_localtime(&tm);

    *p++ = '[';
    p += ngx_snprintf(p, 21, "%02d/%s/%d:%02d:%02d:%02d",
                      tm.ngx_tm_mday, months[tm.ngx_tm_mon],
                      tm.ngx_tm_year + 1900,
                      tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    *p++ = ']';

    *p++ = ' ';

    *p++ = '"';
    ngx_memcpy(p, r->request_line.data, r->request_line.len);
    p += r->request_line.len;
    *p++ = '"';

    *p++ = ' ';

    p += ngx_snprintf(p, 4, "%d", r->headers_out.status);

    *p++ = ' ';

    p += ngx_snprintf(p, 21, QD_FMT, r->connection->sent);

    *p++ = ' ';

    p += ngx_snprintf(p, 21, "%u", r->connection->number);

#if (WIN32)
    *p++ = CR; *p++ = LF;
#else
    *p++ = LF;
#endif

    write(1, line, len);

    return NGX_OK;
}
