
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

    ngx_log_debug(r->connection->log, "log handler");

    /* %a, 20:%c, 22:%d, 3:%s, 20:%b, 5*" ", "2/1: "\r\n" */
#if (WIN32)
    len = 2 + 20 + 22 + 3 + 20 + 5 + + 2;
#else
    len = 2 + 20 + 22 + 3 + 20 + 5 + + 1;
#endif

    len += r->connection->addr_text.len;
    len += r->request_line.len;

    ngx_log_debug(r->connection->log, "log handler: %d" _ len);

    ngx_test_null(line, ngx_palloc(r->pool, len), NGX_ERROR);
    p = line;

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);
    p += r->connection->addr_text.len;

    *p++ = ' ';

    p += ngx_snprintf(p, 21, "%u", r->connection->number);

    *p++ = ' ';

    *p = '\0';
    ngx_log_debug(r->connection->log, "log handler: %s" _ line);

    ngx_localtime(&tm);

    ngx_log_debug(r->connection->log, "log handler: %s" _ line);

    *p++ = '[';
    p += ngx_snprintf(p, 21, "%02d/%s/%d:%02d:%02d:%02d",
                      tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                      tm.ngx_tm_year,
                      tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    *p++ = ']';

    *p++ = ' ';

    *p = '\0';
    ngx_log_debug(r->connection->log, "log handler: %s" _ line);

    *p++ = '"';
    ngx_memcpy(p, r->request_line.data, r->request_line.len);
    p += r->request_line.len;
    *p++ = '"';

    *p++ = ' ';

    p += ngx_snprintf(p, 4, "%d", r->headers_out.status);

    *p++ = ' ';

    p += ngx_snprintf(p, 21, QD_FMT, r->connection->sent);

    *p = '\0';
    ngx_log_debug(r->connection->log, "log handler: %s" _ line);

#if (WIN32)
    *p++ = CR; *p++ = LF;
#else
    *p++ = LF;
#endif

    *p = '\0';
    ngx_log_debug(r->connection->log, "log handler: %s" _ line);

    write(1, line, len);

    return NGX_OK;
}
