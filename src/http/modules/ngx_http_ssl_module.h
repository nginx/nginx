
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_SSL_H_INCLUDED_
#define _NGX_HTTP_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t                      enable;

    ngx_ssl_t                       ssl;

    ngx_flag_t                      prefer_server_ciphers;

    ngx_uint_t                      protocols;

    ngx_int_t                       verify;
    ngx_int_t                       verify_depth;

    ssize_t                         builtin_session_cache;

    time_t                          session_timeout;

    ngx_str_t                       certificate;
    ngx_str_t                       certificate_key;
    ngx_str_t                       client_certificate;

    ngx_str_t                       ciphers;

    ngx_shm_zone_t                 *shm_zone;
} ngx_http_ssl_srv_conf_t;


extern ngx_module_t  ngx_http_ssl_module;


#endif /* _NGX_HTTP_SSL_H_INCLUDED_ */
