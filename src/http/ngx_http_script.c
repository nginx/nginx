
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


char *ngx_http_script_copy(ngx_http_request_t *r,
                           ngx_http_script_code_t *code,
                           char *p, size_t len)
{
    return ngx_cpymem(p, code->offset, code->len < len ? code->len : len);
}


char *ngx_http_script_header_in(ngx_http_request_t *r,
                                ngx_http_script_code_t *code,
                                char *p, size_t len)
{
    ngx_str_t *s;

    s = (ngx_str_t *) (((char *) r->headers_in) + code->offset);

    return ngx_cpymem(p, s->data, s->len < len ? s->len : len);
}


/* the log script codes */

char *ngx_http_script_request_line(ngx_http_request_t *r, char *p, size_t len)
{
    return ngx_cpymem(p, r->request_line.data,
                      r->request_line.len < len ? r->request_line.len : len);
}


char *ngx_http_script_status(ngx_http_request_t *r, char *p, size_t len)
{
    p += ngx_snprintf(p, len, "%d", r->headers_out.status);

    return p;
}


char *ngx_http_script_sent(ngx_http_request_t *r, char *p, size_t len)
{
    p += ngx_snprintf(p, len, OFF_FMT, r->connection->sent);

    return p;
}
