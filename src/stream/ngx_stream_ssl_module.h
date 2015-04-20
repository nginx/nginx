
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_SSL_H_INCLUDED_
#define _NGX_STREAM_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_msec_t       handshake_timeout;

    ngx_flag_t       prefer_server_ciphers;

    ngx_ssl_t        ssl;

    ngx_uint_t       protocols;

    ssize_t          builtin_session_cache;

    time_t           session_timeout;

    ngx_str_t        certificate;
    ngx_str_t        certificate_key;
    ngx_str_t        dhparam;
    ngx_str_t        ecdh_curve;

    ngx_str_t        ciphers;

    ngx_array_t     *passwords;

    ngx_shm_zone_t  *shm_zone;

    ngx_flag_t       session_tickets;
    ngx_array_t     *session_ticket_keys;
} ngx_stream_ssl_conf_t;


extern ngx_module_t  ngx_stream_ssl_module;


#endif /* _NGX_STREAM_SSL_H_INCLUDED_ */
