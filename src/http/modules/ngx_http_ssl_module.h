
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_SSL_H_INCLUDED_
#define _NGX_HTTP_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t      enable;
    ngx_str_t       certificate;
    ngx_str_t       certificate_key;

    ngx_ssl_ctx_t  *ssl_ctx;
} ngx_http_ssl_srv_conf_t;


ngx_int_t ngx_http_ssl_read(ngx_http_request_t *r, u_char *buf, size_t size);
ngx_int_t ngx_http_ssl_shutdown(ngx_http_request_t *r);
ngx_chain_t *ngx_http_ssl_write(ngx_connection_t *c, ngx_chain_t *in,
                                off_t limit);

void ngx_http_ssl_close_connection(SSL *ssl, ngx_log_t *log);


extern ngx_module_t  ngx_http_ssl_module;


#endif /* _NGX_HTTP_SSL_H_INCLUDED_ */
