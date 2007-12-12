
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static u_char error_full_tail[] =
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char error_tail[] =
"<hr><center>nginx</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_msie_stub[] =
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
;


static u_char ngx_http_msie_refresh_head[] =
"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";


static u_char ngx_http_msie_refresh_tail[] =
"\"></head><body></body></html>" CRLF;


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


static char error_401_page[] =
"<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF
;


static char error_402_page[] =
"<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF
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


static char error_406_page[] =
"<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF
;


static char error_408_page[] =
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
;


static char error_409_page[] =
"<html>" CRLF
"<head><title>409 Conflict</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>409 Conflict</h1></center>" CRLF
;


static char error_410_page[] =
"<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>410 Gone</h1></center>" CRLF
;


static char error_411_page[] =
"<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF
;


static char error_412_page[] =
"<html>" CRLF
"<head><title>412 Precondition Failed</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>412 Precondition Failed</h1></center>" CRLF
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


static char error_415_page[] =
"<html>" CRLF
"<head><title>415 Unsupported Media Type</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>415 Unsupported Media Type</h1></center>" CRLF
;


static char error_416_page[] =
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
;


static char error_495_page[] =
"<html>" CRLF
"<head><title>400 The SSL certificate error</title></head>"
CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The SSL certificate error</center>" CRLF
;


static char error_496_page[] =
"<html>" CRLF
"<head><title>400 No required SSL certificate was sent</title></head>"
CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>No required SSL certificate was sent</center>" CRLF
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
"<center><h1>501 Method Not Implemented</h1></center>" CRLF
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


static char error_507_page[] =
"<html>" CRLF
"<head><title>507 Insufficient Storage</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>507 Insufficient Storage</h1></center>" CRLF
;


static ngx_str_t error_pages[] = {

    ngx_null_string,             /* 201, 204 */

#define NGX_HTTP_LEVEL_200  1

    /* ngx_null_string, */       /* 300 */
    ngx_string(error_301_page),
    ngx_string(error_302_page),
    ngx_null_string,             /* 303 */

#define NGX_HTTP_LEVEL_300  3

    ngx_string(error_400_page),
    ngx_string(error_401_page),
    ngx_string(error_402_page),
    ngx_string(error_403_page),
    ngx_string(error_404_page),
    ngx_string(error_405_page),
    ngx_string(error_406_page),
    ngx_null_string,             /* 407 */
    ngx_string(error_408_page),
    ngx_string(error_409_page),
    ngx_string(error_410_page),
    ngx_string(error_411_page),
    ngx_string(error_412_page),
    ngx_string(error_413_page),
    ngx_string(error_414_page),
    ngx_string(error_415_page),
    ngx_string(error_416_page),

#define NGX_HTTP_LEVEL_400  17

    ngx_string(error_495_page),  /* 495, https certificate error */
    ngx_string(error_496_page),  /* 496, https no certificate */
    ngx_string(error_497_page),  /* 497, http to https */
    ngx_string(error_404_page),  /* 498, invalid host name */
    ngx_null_string,             /* 499, client had closed connection */

    ngx_string(error_500_page),
    ngx_string(error_501_page),
    ngx_string(error_502_page),
    ngx_string(error_503_page),
    ngx_string(error_504_page),
    ngx_null_string,             /* 505 */
    ngx_null_string,             /* 506 */
    ngx_string(error_507_page)
};


static ngx_str_t  ngx_http_get_name = { 3, (u_char *) "GET " };


ngx_int_t
ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error)
{
    u_char                    *p;
    size_t                     msie_refresh;
    uintptr_t                  escape;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                 *uri, *location;
    ngx_uint_t                 i, n, err, msie_padding;
    ngx_chain_t               *out, *cl;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %d, \"%V\"", error, &r->uri);

    rc = ngx_http_discard_body(r);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        error = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->err_status = error;

    if (r->keepalive != 0) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close == 1) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
                r->lingering_close = 0;
        }
    }

    r->headers_out.content_type.len = 0;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!r->error_page && clcf->error_pages) {

        if (clcf->recursive_error_pages == 0) {
            r->error_page = 1;
        }

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {

            if (err_page[i].status == error) {
                r->err_status = err_page[i].overwrite;

                r->method = NGX_HTTP_GET;
                r->method_name = ngx_http_get_name;

                uri = &err_page[i].uri;

                if (err_page[i].uri_lengths) {
                    if (ngx_http_script_run(r, uri,
                                            err_page[i].uri_lengths->elts, 0,
                                            err_page[i].uri_values->elts)
                        == NULL)
                    {
                        return NGX_ERROR;
                    }

                    if (r->zero_in_uri) {
                        for (n = 0; n < uri->len; n++) {
                            if (uri->data[n] == '\0') {
                                goto zero;
                            }
                        }

                        r->zero_in_uri = 0;
                    }

                } else {
                    r->zero_in_uri = 0;
                }

            zero:

                if (uri->data[0] == '/') {
                    return ngx_http_internal_redirect(r, uri, NULL);
                }

                if (uri->data[0] == '@') {
                    return ngx_http_named_location(r, uri);
                }

                r->headers_out.location =
                                        ngx_list_push(&r->headers_out.headers);

                if (r->headers_out.location) {
                    error = NGX_HTTP_MOVED_TEMPORARILY;

                    r->err_status = NGX_HTTP_MOVED_TEMPORARILY;

                    r->headers_out.location->hash = 1;
                    r->headers_out.location->key.len = sizeof("Location") - 1;
                    r->headers_out.location->key.data = (u_char *) "Location";
                    r->headers_out.location->value = *uri;

                } else {
                    return NGX_ERROR;
                }
            }
        }
    }

    if (error == NGX_HTTP_CREATED) {
        /* 201 */
        err = 0;
        r->header_only = 1;

    } else if (error == NGX_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error < NGX_HTTP_BAD_REQUEST) {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_LEVEL_200;

    } else if (error < NGX_HTTP_OWN_CODES) {
        /* 4XX */
        err = error - NGX_HTTP_BAD_REQUEST + NGX_HTTP_LEVEL_200
                                           + NGX_HTTP_LEVEL_300;

    } else {
        /* 49X, 5XX */
        err = error - NGX_HTTP_OWN_CODES + NGX_HTTP_LEVEL_200
                                         + NGX_HTTP_LEVEL_300
                                         + NGX_HTTP_LEVEL_400;
        switch (error) {
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
                r->err_status = NGX_HTTP_BAD_REQUEST;
                error = NGX_HTTP_BAD_REQUEST;
                break;
        }
    }

    msie_padding = 0;

    if (!r->zero_body) {
        if (error_pages[err].len) {
            r->headers_out.content_length_n = error_pages[err].len
                + (clcf->server_tokens ? sizeof(error_full_tail) - 1:
                                         sizeof(error_tail) - 1);

            if (clcf->msie_padding
                && r->headers_in.msie
                && r->http_version >= NGX_HTTP_VERSION_10
                && error >= NGX_HTTP_BAD_REQUEST
                && error != NGX_HTTP_REQUEST_URI_TOO_LARGE)
            {
                r->headers_out.content_length_n +=
                                                sizeof(ngx_http_msie_stub) - 1;
                msie_padding = 1;
            }

            r->headers_out.content_type.len = sizeof("text/html") - 1;
            r->headers_out.content_type.data = (u_char *) "text/html";

        } else {
            r->headers_out.content_length_n = -1;
        }

    } else {
        r->headers_out.content_length_n = 0;
        err = 0;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    if (clcf->msie_refresh
        && r->headers_in.msie
        && (error == NGX_HTTP_MOVED_PERMANENTLY
            || error == NGX_HTTP_MOVED_TEMPORARILY))
    {

        location = &r->headers_out.location->value;

        escape = 2 * ngx_escape_uri(NULL, location->data, location->len,
                                    NGX_ESCAPE_REFRESH);

        msie_refresh = sizeof(ngx_http_msie_refresh_head) - 1
                       + escape + location->len
                       + sizeof(ngx_http_msie_refresh_tail) - 1;

        r->err_status = NGX_HTTP_OK;
        r->headers_out.content_type_len = sizeof("text/html") - 1;
        r->headers_out.content_length_n = msie_refresh;
        r->headers_out.location->hash = 0;
        r->headers_out.location = NULL;

    } else {
        location = NULL;
        escape = 0;
        msie_refresh = 0;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }


    if (msie_refresh == 0) {

        if (error_pages[err].len == 0) {
            return NGX_OK;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = error_pages[err].data;
        b->last = error_pages[err].data + error_pages[err].len;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        out = cl;


        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;

        if (clcf->server_tokens) {
            b->pos = error_full_tail;
            b->last = error_full_tail + sizeof(error_full_tail) - 1;
        } else {
            b->pos = error_tail;
            b->last = error_tail + sizeof(error_tail) - 1;
        }

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;

        if (msie_padding) {
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->memory = 1;
            b->pos = ngx_http_msie_stub;
            b->last = ngx_http_msie_stub + sizeof(ngx_http_msie_stub) - 1;

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;
        }

    } else {
        b = ngx_create_temp_buf(r->pool, msie_refresh);
        if (b == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(b->pos, ngx_http_msie_refresh_head,
                       sizeof(ngx_http_msie_refresh_head) - 1);

        if (escape == 0) {
            p = ngx_cpymem(p, location->data, location->len);

        } else {
            p = (u_char *) ngx_escape_uri(p, location->data, location->len,
                                          NGX_ESCAPE_REFRESH);
        }

        b->last = ngx_cpymem(p, ngx_http_msie_refresh_tail,
                             sizeof(ngx_http_msie_refresh_tail) - 1);

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        out = cl;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    cl->next = NULL;

    return ngx_http_output_filter(r, out);
}
