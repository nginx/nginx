
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static char error_tail[] =
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static char msie_stub[] =
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
;


static char error_302_page[] =
"<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>302 Found</h1></center>" CRLF
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


static char error_416_page[] =
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
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
    ngx_null_string,             /* 300 */
    ngx_null_string,             /* 301 */
    ngx_string(error_302_page),
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
    ngx_string(error_416_page),

    ngx_string(error_500_page),
    ngx_null_string,             /* 501 */
    ngx_string(error_502_page),
    ngx_null_string,             /* 503 */
    ngx_string(error_504_page)
};


int ngx_http_special_response_handler(ngx_http_request_t *r, int error)
{
    int          err, rc;
    ngx_hunk_t  *h;

    r->headers_out.status = error;

    if (error < NGX_HTTP_BAD_REQUEST) {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY;

    } else if (error < NGX_HTTP_INTERNAL_SERVER_ERROR) {
        /* 4XX */
        err = error - NGX_HTTP_BAD_REQUEST + 4;

    } else {
        /* 5XX */
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

    if (r->lingering_close == 1) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->lingering_close = 0;
        }
    }

    if (error_pages[err].len) {
        r->headers_out.content_length = error_pages[err].len
                                        + sizeof(error_tail) - 1
                                        + sizeof(msie_stub) - 1;

        ngx_test_null(r->headers_out.content_type,
                      ngx_push_table(r->headers_out.headers),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        r->headers_out.content_type->key.len = 12;
        r->headers_out.content_type->key.data = "Content-Type";
        r->headers_out.content_type->value.len = 9;
        r->headers_out.content_type->value.data = "text/html";

    } else {
        r->headers_out.content_length = -1;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (r->header_only) {
        if (rc == NGX_AGAIN) {
            ngx_http_set_write_handler(r);
            return NGX_AGAIN;
        }

        return NGX_OK;
    }

    if (error_pages[err].len == 0) {
        return NGX_OK;
    }

    ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);

    h->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;
    h->pos = error_pages[err].data;
    h->last = error_pages[err].data + error_pages[err].len;

    if (ngx_http_output_filter(r, h) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);

    h->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;
    h->pos = error_tail;
    h->last = error_tail + sizeof(error_tail) - 1;

    if (1) {
        if (ngx_http_output_filter(r, h) == NGX_ERROR) {
            return NGX_ERROR;
        }

        ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);

        h->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;
        h->pos = msie_stub;
        h->last = msie_stub + sizeof(msie_stub) - 1;
    }

    h->type |= NGX_HUNK_LAST;

    rc = ngx_http_output_filter(r, h);

    if (r->main == NULL) {
        if (rc == NGX_AGAIN) {
            ngx_http_set_write_handler(r);
            return NGX_AGAIN;
        }
    }

    return NGX_OK;

}
