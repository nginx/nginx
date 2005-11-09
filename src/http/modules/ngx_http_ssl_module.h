
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

    ngx_ssl_t       ssl;

    ngx_flag_t      prefer_server_ciphers;

    ngx_uint_t      protocols;

    time_t          session_timeout;

    ngx_str_t       certificate;
    ngx_str_t       certificate_key;

    ngx_str_t       ciphers;
} ngx_http_ssl_srv_conf_t;


extern ngx_module_t  ngx_http_ssl_module;


#endif /* _NGX_HTTP_SSL_H_INCLUDED_ */
