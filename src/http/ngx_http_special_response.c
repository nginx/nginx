
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_http.h>
#include <ngx_http_output_filter.h>


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


static char error_403_page[] =
"<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF
;


static char error_404_page[] =
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
;


static char error_414_page[] =
"<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF
;


static char error_500_page[] =
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
;


static ngx_str_t error_pages[] = {
    { 0, NULL},  /* 301 */
    { 0, NULL},  /* 302 */
    { 0, NULL},  /* 303 */
    { 0, NULL},  /* 304 */

    { sizeof(error_400_page) - 1, error_400_page },
    { 0, NULL},  /* 401 */
    { 0, NULL},  /* 402 */
    { sizeof(error_403_page) - 1, error_403_page },
    { sizeof(error_404_page) - 1, error_404_page },
    { 0, NULL},  /* 405 */
    { 0, NULL},  /* 406 */
    { 0, NULL},  /* 407 */
    { 0, NULL},  /* 408 */
    { 0, NULL},  /* 409 */
    { 0, NULL},  /* 410 */
    { 0, NULL},  /* 411 */
    { 0, NULL},  /* 412 */
    { 0, NULL},  /* 413 */
    { sizeof(error_414_page) - 1, error_414_page },
    { 0, NULL},  /* 415 */
    { 0, NULL},  /* 416 */

    { sizeof(error_500_page) - 1, error_500_page }
};


int ngx_http_special_response(ngx_http_request_t *r, int error)
{
    int          err, len;
    ngx_hunk_t  *message, *tail;

    len = 0;

    r->headers_out.status = error;

    if (error < NGX_HTTP_BAD_REQUEST) {
        err = error - NGX_HTTP_MOVED_PERMANENTLY;

    } else if (error < NGX_HTTP_INTERNAL_SERVER_ERROR) {
        err = error - NGX_HTTP_BAD_REQUEST + 4;

    } else {
        err = error - NGX_HTTP_INTERNAL_SERVER_ERROR + 4 + 17;
    }

    if (r->keepalive != 0) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->keepalive = 0;
        }
    }

    if (error_pages[err].len == 0) {
        r->headers_out.content_length = -1;
    } else {
        r->headers_out.content_length = error_pages[err].len
                                        + len + sizeof(error_tail);
    }

    if (ngx_http_send_header(r) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (error_pages[err].len == 0) {
        return NGX_OK;
    }

    ngx_test_null(message, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)), NGX_ERROR);

    message->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;
    message->pos = error_pages[err].data;
    message->last = error_pages[err].data + error_pages[err].len;

    if (ngx_http_output_filter(r, message) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_test_null(tail, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)), NGX_ERROR);

    tail->type = NGX_HUNK_MEMORY|NGX_HUNK_LAST|NGX_HUNK_IN_MEMORY;
    tail->pos = error_tail;
    tail->last = error_tail + sizeof(error_tail);

    return ngx_http_output_filter(r, tail);
}
