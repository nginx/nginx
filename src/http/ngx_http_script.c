
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


u_char *ngx_http_script_copy(ngx_http_request_t *r, u_char *buf, void *data)
{
    u_char  **p = data;

    ngx_http_script_code_t  *code;

    code = (ngx_http_script_code_t *)
                              ((char *) data - sizeof(ngx_http_script_code_t));

    return ngx_cpymem(buf, *p, code->data_len);
}


u_char *ngx_http_script_header_in(ngx_http_request_t *r,
                                  u_char *buf, void *data)
{
    size_t  *offset = data;

    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) (((char *) r->headers_in) + *offset);

    return ngx_cpymem(p, h->value.data, h->value.len);
}


u_char *ngx_http_script_request_line(ngx_http_request_t *r,
                                     u_char *buf, void *data)
{
    return ngx_cpymem(p, r->request_line.data, r->request_line.len);
}


u_char *ngx_http_script_status(ngx_http_request_t *r, u_char *buf, void *data)
{
    return ngx_sprintf(buf, "%ui", r->headers_out.status);
}


u_char *ngx_http_script_sent(ngx_http_request_t *r, u_char *buf, void *data)
{
    return ngx_sprintf(buf, "%O", r->connection->sent);
}
