
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_IMAP_SSL_H_INCLUDED_
#define _NGX_IMAP_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_imap.h>


#define NGX_IMAP_STARTTLS_OFF   0
#define NGX_IMAP_STARTTLS_ON    1
#define NGX_IMAP_STARTTLS_ONLY  2


typedef struct {
    ngx_flag_t      enable;

    ngx_ssl_t       ssl;

    ngx_flag_t      prefer_server_ciphers;
    ngx_flag_t      starttls;

    ngx_uint_t      protocols;

    time_t          session_timeout;

    ngx_str_t       certificate;
    ngx_str_t       certificate_key;

    ngx_str_t       ciphers;

} ngx_imap_ssl_conf_t;


extern ngx_module_t  ngx_imap_ssl_module;


#endif /* _NGX_IMAP_SSL_H_INCLUDED_ */
