
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_MAIL_SSL_H_INCLUDED_
#define _NGX_MAIL_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>


#define NGX_MAIL_STARTTLS_OFF   0
#define NGX_MAIL_STARTTLS_ON    1
#define NGX_MAIL_STARTTLS_ONLY  2


typedef struct {
    ngx_flag_t       enable;
    ngx_flag_t       prefer_server_ciphers;

    ngx_ssl_t        ssl;

    ngx_uint_t       starttls;
    ngx_uint_t       protocols;

    ssize_t          builtin_session_cache;

    time_t           session_timeout;

    ngx_str_t        certificate;
    ngx_str_t        certificate_key;
    ngx_str_t        dhparam;

    ngx_str_t        ciphers;

    ngx_shm_zone_t  *shm_zone;

    u_char          *file;
    ngx_uint_t       line;
} ngx_mail_ssl_conf_t;


extern ngx_module_t  ngx_mail_ssl_module;


#endif /* _NGX_MAIL_SSL_H_INCLUDED_ */
