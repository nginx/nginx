
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_smtp_module.h>


static void *ngx_mail_smtp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_smtp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_conf_bitmask_t  ngx_mail_smtp_auth_methods[] = {
    { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
    { ngx_string("login"), NGX_MAIL_AUTH_LOGIN_ENABLED },
    { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_mail_smtp_auth_methods_names[] = {
    ngx_string("PLAIN"),
    ngx_string("LOGIN"),
    ngx_null_string,  /* APOP */
    ngx_string("CRAM-MD5")
};


static ngx_mail_protocol_t  ngx_mail_smtp_protocol = {
    ngx_string("smtp"),
    { 25, 465, 587, 0 },
    NGX_MAIL_SMTP_PROTOCOL,

    ngx_mail_smtp_init_session,
    ngx_mail_smtp_init_protocol,
    ngx_mail_smtp_parse_command,
    ngx_mail_smtp_auth_state,

    ngx_string("451 4.3.2 Internal server error" CRLF)
};


static ngx_command_t  ngx_mail_smtp_commands[] = {

    { ngx_string("smtp_client_buffer"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_smtp_srv_conf_t, client_buffer_size),
      NULL },

    { ngx_string("smtp_greeting_delay"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_smtp_srv_conf_t, greeting_delay),
      NULL },

    { ngx_string("smtp_capabilities"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_capabilities,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_smtp_srv_conf_t, capabilities),
      NULL },

    { ngx_string("smtp_auth"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_smtp_srv_conf_t, auth_methods),
      &ngx_mail_smtp_auth_methods },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_smtp_module_ctx = {
    &ngx_mail_smtp_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_smtp_create_srv_conf,         /* create server configuration */
    ngx_mail_smtp_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_mail_smtp_module = {
    NGX_MODULE_V1,
    &ngx_mail_smtp_module_ctx,             /* module context */
    ngx_mail_smtp_commands,                /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_mail_smtp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_smtp_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_smtp_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->client_buffer_size = NGX_CONF_UNSET_SIZE;
    sscf->greeting_delay = NGX_CONF_UNSET_MSEC;

    if (ngx_array_init(&sscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    return sscf;
}


static char *
ngx_mail_smtp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_smtp_srv_conf_t *prev = parent;
    ngx_mail_smtp_srv_conf_t *conf = child;

    u_char                    *p, *auth;
    size_t                     size;
    ngx_str_t                 *c;
    ngx_uint_t                 i, m;
    ngx_mail_core_srv_conf_t  *cscf;

    ngx_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_msec_value(conf->greeting_delay,
                              prev->greeting_delay, 0);

    ngx_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (NGX_CONF_BITMASK_SET
                               |NGX_MAIL_AUTH_PLAIN_ENABLED
                               |NGX_MAIL_AUTH_LOGIN_ENABLED));


    cscf = ngx_mail_conf_get_module_srv_conf(cf, ngx_mail_core_module);

    size = sizeof("220  ESMTP ready" CRLF) - 1 + cscf->server_name.len;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->greeting.len = size;
    conf->greeting.data = p;

    *p++ = '2'; *p++ = '2'; *p++ = '0'; *p++ = ' ';
    p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    ngx_memcpy(p, " ESMTP ready" CRLF, sizeof(" ESMTP ready" CRLF) - 1);


    size = sizeof("250 " CRLF) - 1 + cscf->server_name.len;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->server_name.len = size;
    conf->server_name.data = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
    p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p = LF;


    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    size = sizeof("250-") - 1 + cscf->server_name.len + sizeof(CRLF) - 1
           + sizeof("250 AUTH") - 1 + sizeof(CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += sizeof("250 ") - 1 + c[i].len + sizeof(CRLF) - 1;
    }

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_CRAM_MD5_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + ngx_mail_smtp_auth_methods_names[i].len;
        }
    }

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
    p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p++ = LF;

    for (i = 0; i < conf->capabilities.nelts; i++) {
        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
        p = ngx_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    auth = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
    *p++ = 'A'; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_CRAM_MD5_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = ngx_cpymem(p, ngx_mail_smtp_auth_methods_names[i].data,
                           ngx_mail_smtp_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p = LF;

    size += sizeof("250 STARTTLS" CRLF) - 1;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = ngx_cpymem(p, conf->capability.data,
                   conf->capability.len);

    p = ngx_cpymem(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);
    *p++ = CR; *p = LF;

    p = conf->starttls_capability.data
        + (auth - conf->capability.data) + 3;
    *p = '-';

    size = (auth - conf->capability.data)
            + sizeof("250 STARTTLS" CRLF) - 1;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = ngx_cpymem(p, conf->capability.data,
                   auth - conf->capability.data);

    ngx_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    return NGX_CONF_OK;
}
