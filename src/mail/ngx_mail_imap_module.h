
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_MAIL_IMAP_MODULE_H_INCLUDED_
#define _NGX_MAIL_IMAP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>


typedef struct {
    size_t       client_buffer_size;

    ngx_str_t    capability;
    ngx_str_t    starttls_capability;
    ngx_str_t    starttls_only_capability;

    ngx_uint_t   auth_methods;

    ngx_array_t  capabilities;
} ngx_mail_imap_srv_conf_t;


void ngx_mail_imap_init_session(ngx_mail_session_t *s, ngx_connection_t *c);
void ngx_mail_imap_init_protocol(ngx_event_t *rev);
void ngx_mail_imap_auth_state(ngx_event_t *rev);
ngx_int_t ngx_mail_imap_parse_command(ngx_mail_session_t *s);


extern ngx_module_t  ngx_mail_imap_module;


#endif /* _NGX_MAIL_IMAP_MODULE_H_INCLUDED_ */
