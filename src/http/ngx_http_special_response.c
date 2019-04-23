
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static ngx_int_t ngx_http_send_error_page(ngx_http_request_t *r,
    ngx_http_err_page_t *err_page);
static ngx_int_t ngx_http_send_special_response(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_uint_t err);
static ngx_int_t ngx_http_send_refresh(ngx_http_request_t *r);


static u_char ngx_http_error_full_tail[] =
"</div>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_error_build_tail[] =
"</div>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_error_tail[] =
"<hr><center>nginx</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_msie_padding[] =
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
;


static u_char ngx_http_msie_refresh_head[] =
"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";


static u_char ngx_http_msie_refresh_tail[] =
"\"></head><body></body></html>" CRLF;


static char ngx_http_error_301_page[] =
"<html><head>" CRLF
"<title>Moved Permanently (301)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Moved Permanently (301)</h3>" CRLF
;


static char ngx_http_error_302_page[] =
"<html><head>" CRLF
"<title>Found (302)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Found (302)</h3>" CRLF
;


static char ngx_http_error_303_page[] =
"<html><head>" CRLF
"<title>See Other (303)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>See Other (303)</h3>" CRLF
;


static char ngx_http_error_307_page[] =
"<html><head>" CRLF
"<title>Temporary Redirect (307)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Temporary Redirect (307)</h3>" CRLF
;


static char ngx_http_error_308_page[] =
"<html><head>" CRLF
"<title>Permanent Redirect (308)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Permanent Redirect (308)</h3>" CRLF
;


static char ngx_http_error_400_page[] =
"<html><head>" CRLF
"<title>Bad Request (400)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Bad Request (400)</h3>" CRLF
;


static char ngx_http_error_401_page[] =
"<html><head>" CRLF
"<title>Authorization Required (401)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Authorization Required (401)</h3>" CRLF
;


static char ngx_http_error_402_page[] =
"<html><head>" CRLF
"<title>Payment Required (402)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Payment Required (402)</h3>" CRLF
;


static char ngx_http_error_403_page[] =
"<html><head>" CRLF
"<title>Forbidden (403)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Forbidden (403)</h3>" CRLF
;


static char ngx_http_error_404_page[] =
"<html><head>" CRLF
"<title>Not Found (404)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Not Found (404)</h3>" CRLF
;


static char ngx_http_error_405_page[] =
"<html><head>" CRLF
"<title>Not Allowed (405)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Not Allowed (405)</h3>" CRLF
;


static char ngx_http_error_406_page[] =
"<html><head>" CRLF
"<title>Not Acceptable (406)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Not Acceptable (406)</h3>" CRLF
;


static char ngx_http_error_408_page[] =
"<html><head>" CRLF
"<title>Request Time-out (408)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Request Time-out (408)</h3>" CRLF
;


static char ngx_http_error_409_page[] =
"<html><head>" CRLF
"<title>Conflict (409)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Conflict (409)</h3>" CRLF
;


static char ngx_http_error_410_page[] =
"<html><head>" CRLF
"<title>Gone (410)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Gone (410)</h3>" CRLF
;


static char ngx_http_error_411_page[] =
"<html><head>" CRLF
"<title>Length Required (411)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Length Required (411)</h3>" CRLF
;


static char ngx_http_error_412_page[] =
"<html><head>" CRLF
"<title>Precondition Failed (412)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Precondition Failed (412)</h3>" CRLF
;


static char ngx_http_error_413_page[] =
"<html><head>" CRLF
"<title>Request Entity Too Large (413)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Request Entity Too Large (413)</h3>" CRLF
;


static char ngx_http_error_414_page[] =
"<html><head>" CRLF
"<title>Request-URI Too Large (414)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Request-URI Too Large (414)</h3>" CRLF
;


static char ngx_http_error_415_page[] =
"<html><head>" CRLF
"<title>Unsupported Media Type (415)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Unsupported Media Type (415)</h3>" CRLF
;


static char ngx_http_error_416_page[] =
"<html><head>" CRLF
"<title>Requested Range Not Satisfiable (416)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Requested Range Not Satisfiable (416)</h3>" CRLF
;


static char ngx_http_error_421_page[] =
"<html><head>" CRLF
"<title>Too Many Concurrent SMTP Connections (421)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Too Many Concurrent SMTP Connections (421)</h3>" CRLF
;


static char ngx_http_error_429_page[] =
"<html><head>" CRLF
"<title>Too Many Requests (429)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Too Many Requests (429)</h3>" CRLF
;


static char ngx_http_error_494_page[] =
"<html><head>" CRLF
"<title>Request Header Or Cookie Too Large (400)</title></head>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Bad Request (400)</h3>" CRLF
"<h3>Request Header Or Cookie Too Large</h3>" CRLF
;


static char ngx_http_error_495_page[] =
"<html><head>" CRLF
"<title>The SSL certificate error (400)</title></head>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Bad Request (400)</h3>" CRLF
"<h3>The SSL certificate error</h3>" CRLF
;


static char ngx_http_error_496_page[] =
"<html><head>" CRLF
"<title>No required SSL certificate was sent (400)</title></head>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Bad Request (400)</h3>" CRLF
"<h3>No required SSL certificate was sent</h3>" CRLF
;


static char ngx_http_error_497_page[] =
"<html><head>" CRLF
"<title>The plain HTTP request was sent to HTTPS port (400)</title></head>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Bad Request (400)</h3>" CRLF
"<h3>The plain HTTP request was sent to HTTPS port</h3>" CRLF
;


static char ngx_http_error_500_page[] =
"<html><head>" CRLF
"<title>Internal Server Error (500)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Internal Server Error (500)</h3>" CRLF
;


static char ngx_http_error_501_page[] =
"<html><head>" CRLF
"<title>Not Implemented (501)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Not Implemented (501)</h3>" CRLF
;


static char ngx_http_error_502_page[] =
"<html><head>" CRLF
"<title>Bad Gateway (502)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Bad Gateway (502)</h3>" CRLF
;


static char ngx_http_error_503_page[] =
"<html><head>" CRLF
"<title>Service Temporarily Unavailable (503)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Service Temporarily Unavailable (503)</h3>" CRLF
;


static char ngx_http_error_504_page[] =
"<html><head>" CRLF
"<title>Gateway Time-out (504)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Gateway Time-out (504)</h3>" CRLF
;


static char ngx_http_error_505_page[] =
"<html><head>" CRLF
"<title>HTTP Version Not Supported (505)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>HTTP Version Not Supported (505)</h3>" CRLF
;


static char ngx_http_error_507_page[] =
"<html><head>" CRLF
"<title>Insufficient Storage (507)</title>" CRLF
"<style>*{margin:0;padding:0;}body{background:#eee;color:#fff;}div{background:#007878;padding:70px;margin:50px 0;}h3{color:#ddd;}</style>" CRLF
"</head><body><div>" CRLF
"<h1>Arvan Cloud</h1>" CRLF
"<h3>Insufficient Storage (507)</h3>" CRLF
;


static ngx_str_t ngx_http_error_pages[] = {

    ngx_null_string,                     /* 201, 204 */

#define NGX_HTTP_LAST_2XX  202
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 201)

    /* ngx_null_string, */               /* 300 */
    ngx_string(ngx_http_error_301_page),
    ngx_string(ngx_http_error_302_page),
    ngx_string(ngx_http_error_303_page),
    ngx_null_string,                     /* 304 */
    ngx_null_string,                     /* 305 */
    ngx_null_string,                     /* 306 */
    ngx_string(ngx_http_error_307_page),
    ngx_string(ngx_http_error_308_page),

#define NGX_HTTP_LAST_3XX  309
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string(ngx_http_error_400_page),
    ngx_string(ngx_http_error_401_page),
    ngx_string(ngx_http_error_402_page),
    ngx_string(ngx_http_error_403_page),
    ngx_string(ngx_http_error_404_page),
    ngx_string(ngx_http_error_405_page),
    ngx_string(ngx_http_error_406_page),
    ngx_null_string,                     /* 407 */
    ngx_string(ngx_http_error_408_page),
    ngx_string(ngx_http_error_409_page),
    ngx_string(ngx_http_error_410_page),
    ngx_string(ngx_http_error_411_page),
    ngx_string(ngx_http_error_412_page),
    ngx_string(ngx_http_error_413_page),
    ngx_string(ngx_http_error_414_page),
    ngx_string(ngx_http_error_415_page),
    ngx_string(ngx_http_error_416_page),
    ngx_null_string,                     /* 417 */
    ngx_null_string,                     /* 418 */
    ngx_null_string,                     /* 419 */
    ngx_null_string,                     /* 420 */
    ngx_string(ngx_http_error_421_page),
    ngx_null_string,                     /* 422 */
    ngx_null_string,                     /* 423 */
    ngx_null_string,                     /* 424 */
    ngx_null_string,                     /* 425 */
    ngx_null_string,                     /* 426 */
    ngx_null_string,                     /* 427 */
    ngx_null_string,                     /* 428 */
    ngx_string(ngx_http_error_429_page),

#define NGX_HTTP_LAST_4XX  430
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string(ngx_http_error_494_page), /* 494, request header too large */
    ngx_string(ngx_http_error_495_page), /* 495, https certificate error */
    ngx_string(ngx_http_error_496_page), /* 496, https no certificate */
    ngx_string(ngx_http_error_497_page), /* 497, http to https */
    ngx_string(ngx_http_error_404_page), /* 498, canceled */
    ngx_null_string,                     /* 499, client has closed connection */

    ngx_string(ngx_http_error_500_page),
    ngx_string(ngx_http_error_501_page),
    ngx_string(ngx_http_error_502_page),
    ngx_string(ngx_http_error_503_page),
    ngx_string(ngx_http_error_504_page),
    ngx_string(ngx_http_error_505_page),
    ngx_null_string,                     /* 506 */
    ngx_string(ngx_http_error_507_page)

#define NGX_HTTP_LAST_5XX  508

};


ngx_int_t
ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error)
{
    ngx_uint_t                 i, err;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %i, \"%V?%V\"",
                   error, &r->uri, &r->args);

    r->err_status = error;

    if (r->keepalive) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
            case NGX_HTTP_NOT_IMPLEMENTED:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close) {
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

    if (!r->error_page && clcf->error_pages && r->uri_changes != 0) {

        if (clcf->recursive_error_pages == 0) {
            r->error_page = 1;
        }

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {
            if (err_page[i].status == error) {
                return ngx_http_send_error_page(r, &err_page[i]);
            }
        }
    }

    r->expect_tested = 1;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        r->keepalive = 0;
    }

    if (clcf->msie_refresh
        && r->headers_in.msie
        && (error == NGX_HTTP_MOVED_PERMANENTLY
            || error == NGX_HTTP_MOVED_TEMPORARILY))
    {
        return ngx_http_send_refresh(r);
    }

    if (error == NGX_HTTP_CREATED) {
        /* 201 */
        err = 0;

    } else if (error == NGX_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error >= NGX_HTTP_MOVED_PERMANENTLY
               && error < NGX_HTTP_LAST_3XX)
    {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;

    } else if (error >= NGX_HTTP_BAD_REQUEST
               && error < NGX_HTTP_LAST_4XX)
    {
        /* 4XX */
        err = error - NGX_HTTP_BAD_REQUEST + NGX_HTTP_OFF_4XX;

    } else if (error >= NGX_HTTP_NGINX_CODES
               && error < NGX_HTTP_LAST_5XX)
    {
        /* 49X, 5XX */
        err = error - NGX_HTTP_NGINX_CODES + NGX_HTTP_OFF_5XX;
        switch (error) {
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTPS_CERT_ERROR:
            case NGX_HTTPS_NO_CERT:
            case NGX_HTTP_REQUEST_HEADER_TOO_LARGE:
                r->err_status = NGX_HTTP_BAD_REQUEST;
        }

    } else {
        /* unknown code, zero body */
        err = 0;
    }

    return ngx_http_send_special_response(r, clcf, err);
}


ngx_int_t
ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_module_t *m,
    ngx_int_t error)
{
    void       *ctx;
    ngx_int_t   rc;

    ngx_http_clean_header(r);

    ctx = NULL;

    if (m) {
        ctx = r->ctx[m->ctx_index];
    }

    /* clear the modules contexts */
    ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);

    if (m) {
        r->ctx[m->ctx_index] = ctx;
    }

    r->filter_finalize = 1;

    rc = ngx_http_special_response_handler(r, error);

    /* NGX_ERROR resets any pending data */

    switch (rc) {

    case NGX_OK:
    case NGX_DONE:
        return NGX_ERROR;

    default:
        return rc;
    }
}


void
ngx_http_clean_header(ngx_http_request_t *r)
{
    ngx_memzero(&r->headers_out.status,
                sizeof(ngx_http_headers_out_t)
                    - offsetof(ngx_http_headers_out_t, status));

    r->headers_out.headers.part.nelts = 0;
    r->headers_out.headers.part.next = NULL;
    r->headers_out.headers.last = &r->headers_out.headers.part;

    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;
}


static ngx_int_t
ngx_http_send_error_page(ngx_http_request_t *r, ngx_http_err_page_t *err_page)
{
    ngx_int_t                  overwrite;
    ngx_str_t                  uri, args;
    ngx_table_elt_t           *location;
    ngx_http_core_loc_conf_t  *clcf;

    overwrite = err_page->overwrite;

    if (overwrite && overwrite != NGX_HTTP_OK) {
        r->expect_tested = 1;
    }

    if (overwrite >= 0) {
        r->err_status = overwrite;
    }

    if (ngx_http_complex_value(r, &err_page->value, &uri) != NGX_OK) {
        return NGX_ERROR;
    }

    if (uri.len && uri.data[0] == '/') {

        if (err_page->value.lengths) {
            ngx_http_split_args(r, &uri, &args);

        } else {
            args = err_page->args;
        }

        if (r->method != NGX_HTTP_HEAD) {
            r->method = NGX_HTTP_GET;
            r->method_name = ngx_http_core_get_method;
        }

        return ngx_http_internal_redirect(r, &uri, &args);
    }

    if (uri.len && uri.data[0] == '@') {
        return ngx_http_named_location(r, &uri);
    }

    location = ngx_list_push(&r->headers_out.headers);

    if (location == NULL) {
        return NGX_ERROR;
    }

    if (overwrite != NGX_HTTP_MOVED_PERMANENTLY
        && overwrite != NGX_HTTP_MOVED_TEMPORARILY
        && overwrite != NGX_HTTP_SEE_OTHER
        && overwrite != NGX_HTTP_TEMPORARY_REDIRECT
        && overwrite != NGX_HTTP_PERMANENT_REDIRECT)
    {
        r->err_status = NGX_HTTP_MOVED_TEMPORARILY;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = uri;

    ngx_http_clear_location(r);

    r->headers_out.location = location;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->msie_refresh && r->headers_in.msie) {
        return ngx_http_send_refresh(r);
    }

    return ngx_http_send_special_response(r, clcf, r->err_status
                                                   - NGX_HTTP_MOVED_PERMANENTLY
                                                   + NGX_HTTP_OFF_3XX);
}


static ngx_int_t
ngx_http_send_special_response(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_uint_t err)
{
    u_char       *tail;
    size_t        len;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_uint_t    msie_padding;
    ngx_chain_t   out[3];

    if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
        len = sizeof(ngx_http_error_full_tail) - 1;
        tail = ngx_http_error_full_tail;

    } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
        len = sizeof(ngx_http_error_build_tail) - 1;
        tail = ngx_http_error_build_tail;

    } else {
        len = sizeof(ngx_http_error_tail) - 1;
        tail = ngx_http_error_tail;
    }

    msie_padding = 0;

    if (ngx_http_error_pages[err].len) {
        r->headers_out.content_length_n = ngx_http_error_pages[err].len + len;
        if (clcf->msie_padding
            && (r->headers_in.msie || r->headers_in.chrome)
            && r->http_version >= NGX_HTTP_VERSION_10
            && err >= NGX_HTTP_OFF_4XX)
        {
            r->headers_out.content_length_n +=
                                         sizeof(ngx_http_msie_padding) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.content_type_lowcase = NULL;

    } else {
        r->headers_out.content_length_n = 0;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    if (ngx_http_error_pages[err].len == 0) {
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;
    b->pos = ngx_http_error_pages[err].data;
    b->last = ngx_http_error_pages[err].data + ngx_http_error_pages[err].len;

    out[0].buf = b;
    out[0].next = &out[1];

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;

    b->pos = tail;
    b->last = tail + len;

    out[1].buf = b;
    out[1].next = NULL;

    if (msie_padding) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = ngx_http_msie_padding;
        b->last = ngx_http_msie_padding + sizeof(ngx_http_msie_padding) - 1;

        out[1].next = &out[2];
        out[2].buf = b;
        out[2].next = NULL;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    return ngx_http_output_filter(r, &out[0]);
}


static ngx_int_t
ngx_http_send_refresh(ngx_http_request_t *r)
{
    u_char       *p, *location;
    size_t        len, size;
    uintptr_t     escape;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    escape = 2 * ngx_escape_uri(NULL, location, len, NGX_ESCAPE_REFRESH);

    size = sizeof(ngx_http_msie_refresh_head) - 1
           + escape + len
           + sizeof(ngx_http_msie_refresh_tail) - 1;

    r->err_status = NGX_HTTP_OK;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_lowcase = NULL;

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = size;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(b->pos, ngx_http_msie_refresh_head,
                   sizeof(ngx_http_msie_refresh_head) - 1);

    if (escape == 0) {
        p = ngx_cpymem(p, location, len);

    } else {
        p = (u_char *) ngx_escape_uri(p, location, len, NGX_ESCAPE_REFRESH);
    }

    b->last = ngx_cpymem(p, ngx_http_msie_refresh_tail,
                         sizeof(ngx_http_msie_refresh_tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
