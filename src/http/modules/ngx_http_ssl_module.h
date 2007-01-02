
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_SSL_H_INCLUDED_
#define _NGX_HTTP_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_ssl_cached_sess_s  ngx_http_ssl_cached_sess_t;


typedef struct {
    ngx_rbtree_node_t               node;
    u_char                         *id;
    size_t                          len;
    ngx_http_ssl_cached_sess_t     *session;
} ngx_http_ssl_sess_id_t;


struct ngx_http_ssl_cached_sess_s {
    ngx_http_ssl_cached_sess_t     *prev;
    ngx_http_ssl_cached_sess_t     *next;
    time_t                          expire;
    ngx_http_ssl_sess_id_t         *sess_id;
    u_char                          asn1[1];
};


typedef struct {
    ngx_rbtree_t                   *session_rbtree;
    ngx_http_ssl_cached_sess_t      session_cache_head;
    ngx_http_ssl_cached_sess_t      session_cache_tail;
} ngx_http_ssl_sesssion_cache_t;


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
