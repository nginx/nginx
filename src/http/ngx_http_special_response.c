
#include <ngx_config.h>
#include <ngx_core.h>

#include <nginx.h>

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


static char error_405_page[] =
"<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF
;


static char error_408_page[] =
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
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


static char error_502_page[] =
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
;


static char error_504_page[] =
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
;


static ngx_str_t error_pages[] = {
    ngx_null_string,             /* 301 */
    ngx_null_string,             /* 302 */
    ngx_null_string,             /* 303 */

    ngx_string(error_400_page),
    ngx_null_string,             /* 401 */
    ngx_null_string,             /* 402 */
    ngx_string(error_403_page),
    ngx_string(error_404_page),
    ngx_string(error_405_page),
    ngx_null_string,             /* 406 */
    ngx_null_string,             /* 407 */
    ngx_string(error_408_page),
    ngx_null_string,             /* 409 */
    ngx_null_string,             /* 410 */
    ngx_null_string,             /* 411 */
    ngx_null_string,             /* 412 */
    ngx_null_string,             /* 413 */
    ngx_string(error_414_page),
    ngx_null_string,             /* 415 */
    ngx_null_string,             /* 416 */

    ngx_string(error_500_page),
    ngx_null_string,             /* 501 */
    ngx_string(error_502_page),
    ngx_null_string,             /* 503 */
    ngx_string(error_504_page)
};


int ngx_http_special_response_handler(ngx_http_request_t *r, int error)
{
    int          err, len;
    ngx_hunk_t  *message, *tail;

    len = 0;

    r->headers_out.status = error;

    if (error < NGX_HTTP_BAD_REQUEST) {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY;

    } else {
        ngx_test_null(r->headers_out.content_type,
                      ngx_push_table(r->headers_out.headers),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        r->headers_out.content_type->key.len = 12;
        r->headers_out.content_type->key.data = "Content-Type";
        r->headers_out.content_type->value.len = 9;
        r->headers_out.content_type->value.data = "text/html";

        if (error < NGX_HTTP_INTERNAL_SERVER_ERROR) {
            /* 4XX */
            err = error - NGX_HTTP_BAD_REQUEST + 3;

        } else {
            /* 5XX */
            err = error - NGX_HTTP_INTERNAL_SERVER_ERROR + 3 + 17;
        }
    }

    if (r->keepalive != 0) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close == 1) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->lingering_close = 0;
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
