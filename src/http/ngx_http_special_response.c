
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static u_char error_tail[] =
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char msie_stub[] =
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
;


static char error_301_page[] =
"<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF
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


static char error_413_page[] =
"<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF
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


static char error_497_page[] =
"<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
;


static char error_500_page[] =
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
;


static char error_501_page[] =
"<html>" CRLF
"<head><title>501 Method Not Implemented</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>500 Method Not Implemented</h1></center>" CRLF
;


static char error_502_page[] =
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
;


static char error_503_page[] =
"<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
;


static char error_504_page[] =
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
;


static ngx_str_t error_pages[] = {
 /* ngx_null_string, */          /* 300 */
    ngx_string(error_301_page),
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
    ngx_string(error_413_page),
    ngx_string(error_414_page),
    ngx_null_string,             /* 415 */
    ngx_string(error_416_page),

    ngx_string(error_497_page),  /* 497, http to https */
    ngx_string(error_404_page),  /* 498, invalid host name */
    ngx_null_string,             /* 499, client closed connection */

    ngx_string(error_500_page),
    ngx_string(error_501_page),
    ngx_string(error_502_page),
    ngx_string(error_503_page),
    ngx_string(error_504_page)
};


ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r, int error)
{
    ngx_int_t                  rc;
    ngx_uint_t                 err, i, msie_padding;
    ngx_buf_t                 *b;
    ngx_chain_t               *out, **ll, *cl;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    rc = ngx_http_discard_body(r);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        error = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = error;

    if (r->keepalive != 0) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close == 1) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_TO_HTTPS:
                r->lingering_close = 0;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->err_ctx == NULL && clcf->error_pages) {
        err_page = clcf->error_pages->elts;
        for (i = 0; i < clcf->error_pages->nelts; i++) {
            if (err_page[i].status == error) {
                if (err_page[i].overwrite) {
                    r->err_status = err_page[i].overwrite;
                } else {
                    r->err_status = error;
                }
                r->err_ctx = r->ctx;
                return ngx_http_internal_redirect(r, &err_page[i].uri, NULL);
            }
        }
    }

    if (error < NGX_HTTP_BAD_REQUEST) {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY;

    } else if (error < NGX_HTTP_NGX_CODES) {
        /* 4XX */
        err = error - NGX_HTTP_BAD_REQUEST + 3;

    } else {
        /* 49X, 5XX */
        err = error - NGX_HTTP_NGX_CODES + 3 + 17;

        switch (error) {
            case NGX_HTTP_TO_HTTPS:
                r->headers_out.status = NGX_HTTP_BAD_REQUEST;
                error = NGX_HTTP_BAD_REQUEST;
                break;

            case NGX_HTTP_INVALID_HOST:
                r->headers_out.status = NGX_HTTP_NOT_FOUND;
                error = NGX_HTTP_NOT_FOUND;
                break;
        }
    }

    msie_padding = 0;

    if (error_pages[err].len) {
        r->headers_out.content_length_n = error_pages[err].len
                                          + sizeof(error_tail) - 1;

        if (clcf->msie_padding
            && r->headers_in.msie
            && r->http_version >= NGX_HTTP_VERSION_10
            && error >= NGX_HTTP_BAD_REQUEST
            && error != NGX_HTTP_REQUEST_URI_TOO_LARGE)
        {
            r->headers_out.content_length_n += sizeof(msie_stub) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.content_type == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.content_type->key.len = sizeof("Content-Type") - 1;
        r->headers_out.content_type->key.data = (u_char *) "Content-Type";
        r->headers_out.content_type->value.len = sizeof("text/html") - 1;
        r->headers_out.content_type->value.data = (u_char *) "text/html";

    } else {
        r->headers_out.content_length_n = -1;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->key.len = 0;
        r->headers_out.content_length = NULL;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    if (error_pages[err].len == 0) {
        return NGX_OK;
    }

    out = NULL;
    ll = NULL;

    if (!(b = ngx_calloc_buf(r->pool))) {
        return NGX_ERROR;
    }
    b->memory = 1;
    b->pos = error_pages[err].data;
    b->last = error_pages[err].data + error_pages[err].len;

    ngx_alloc_link_and_set_buf(cl, b, r->pool, NGX_ERROR);
    ngx_chain_add_link(out, ll, cl);


    if (!(b = ngx_calloc_buf(r->pool))) {
        return NGX_ERROR;
    }
    b->memory = 1;
    b->pos = error_tail;
    b->last = error_tail + sizeof(error_tail) - 1;

    ngx_alloc_link_and_set_buf(cl, b, r->pool, NGX_ERROR);
    ngx_chain_add_link(out, ll, cl);

    if (msie_padding) {
        if (!(b = ngx_calloc_buf(r->pool))) {
            return NGX_ERROR;
        }
        b->memory = 1;
        b->pos = msie_stub;
        b->last = msie_stub + sizeof(msie_stub) - 1;

        ngx_alloc_link_and_set_buf(cl, b, r->pool, NGX_ERROR);
        ngx_chain_add_link(out, ll, cl);
    }

    b->last_buf = 1;

    return ngx_http_output_filter(r, out);
}
