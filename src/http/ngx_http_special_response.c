
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_http.h>

static char error_tail[] =
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;

static char error_400_page[] =
"<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
;

static char error_404_page[] =
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
;


static ngx_str_t error_pages[] = {
    { 0, NULL},  /* 301 */
    { 0, NULL},  /* 302 */
    { 0, NULL},  /* 303 */
    { 0, NULL},  /* 304 */

    { sizeof(error_400_page) - 1, error_400_page },
    { 0, NULL},  /* 401 */
    { 0, NULL},  /* 402 */
    { 0, NULL},  /* 403 */
    { sizeof(error_404_page) - 1, error_404_page },

    { 0, NULL}   /* 500 */
};

int ngx_http_special_response(ngx_http_request_t *r, int error)
{
    int  rc, err, len;
    ngx_hunk_t  *message, *tail;

    len = 0;

    r->headers_out.status = error;

    if (error < NGX_HTTP_BAD_REQUEST)
        err = error - NGX_HTTP_MOVED_PERMANENTLY;

    else if (error < NGX_HTTP_INTERNAL_SERVER_ERROR)
        err = error - NGX_HTTP_BAD_REQUEST + 4;

    else
        err = NGX_HTTP_INTERNAL_SERVER_ERROR + 4 + 5;

    if (error_pages[err].len == 0)
        r->headers_out.content_length = -1;
    else
        r->headers_out.content_length = error_pages[err].len
                                        + len + sizeof(error_tail);

    ngx_http_send_header(r);

    if (error_pages[err].len == 0)
        return NGX_OK;

    ngx_test_null(message, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    message->type = NGX_HUNK_MEMORY;
    message->pos.mem = error_pages[err].data;
    message->last.mem = error_pages[err].data + error_pages[err].len;

    rc = ngx_http_output_filter(r, message);

    ngx_test_null(tail, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    tail->type = NGX_HUNK_MEMORY|NGX_HUNK_LAST;
    tail->pos.mem = error_tail;
    tail->last.mem = error_tail + sizeof(error_tail);

    rc = ngx_http_output_filter(r, tail);
}
