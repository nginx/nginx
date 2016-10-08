
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_pop3_module.h>


static void *ngx_mail_pop3_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_pop3_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_str_t  ngx_mail_pop3_default_capabilities[] = {
    ngx_string("TOP"),
    ngx_string("USER"),
    ngx_string("UIDL"),
    ngx_null_string
};


static ngx_conf_bitmask_t  ngx_mail_pop3_auth_methods[] = {
    { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
    { ngx_string("apop"), NGX_MAIL_AUTH_APOP_ENABLED },
    { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
    { ngx_string("external"), NGX_MAIL_AUTH_EXTERNAL_ENABLED },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_mail_pop3_auth_methods_names[] = {
    ngx_string("PLAIN"),
    ngx_string("LOGIN"),
    ngx_null_string,  /* APOP */
    ngx_string("CRAM-MD5"),
    ngx_string("EXTERNAL"),
    ngx_null_string   /* NONE */
};


static ngx_mail_protocol_t  ngx_mail_pop3_protocol = {
    ngx_string("pop3"),
    { 110, 995, 0, 0 },
    NGX_MAIL_POP3_PROTOCOL,

    ngx_mail_pop3_init_session,
    ngx_mail_pop3_init_protocol,
    ngx_mail_pop3_parse_command,
    ngx_mail_pop3_auth_state,

    ngx_string("-ERR internal server error" CRLF),
    ngx_string("-ERR SSL certificate error" CRLF),
    ngx_string("-ERR No required SSL certificate" CRLF)
};


static ngx_command_t  ngx_mail_pop3_commands[] = {

    { ngx_string("pop3_capabilities"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_capabilities,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_pop3_srv_conf_t, capabilities),
      NULL },

    { ngx_string("pop3_auth"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_pop3_srv_conf_t, auth_methods),
      &ngx_mail_pop3_auth_methods },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_pop3_module_ctx = {
    &ngx_mail_pop3_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_pop3_create_srv_conf,         /* create server configuration */
    ngx_mail_pop3_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_mail_pop3_module = {
    NGX_MODULE_V1,
    &ngx_mail_pop3_module_ctx,             /* module context */
    ngx_mail_pop3_commands,                /* module directives */
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
ngx_mail_pop3_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_pop3_srv_conf_t  *pscf;

    pscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_pop3_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&pscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    return pscf;
}


static char *
ngx_mail_pop3_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_pop3_srv_conf_t *prev = parent;
    ngx_mail_pop3_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size, stls_only_size;
    ngx_str_t   *c, *d;
    ngx_uint_t   i, m;

    ngx_conf_merge_bitmask_value(conf->auth_methods,
                                 prev->auth_methods,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_MAIL_AUTH_PLAIN_ENABLED));

    if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
        conf->auth_methods |= NGX_MAIL_AUTH_LOGIN_ENABLED;
    }

    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = ngx_mail_pop3_default_capabilities; d->len; d++) {
            c = ngx_array_push(&conf->capabilities);
            if (c == NULL) {
                return NGX_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("+OK Capability list follows" CRLF) - 1
           + sizeof("." CRLF) - 1;

    stls_only_size = size + sizeof("STLS" CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += c[i].len + sizeof(CRLF) - 1;

        if (ngx_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        stls_only_size += c[i].len + sizeof(CRLF) - 1;
    }

    size += sizeof("SASL") - 1 + sizeof(CRLF) - 1;

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + ngx_mail_pop3_auth_methods_names[i].len;
        }
    }

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = ngx_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        p = ngx_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = ngx_cpymem(p, "SASL", sizeof("SASL") - 1);

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = ngx_cpymem(p, ngx_mail_pop3_auth_methods_names[i].data,
                           ngx_mail_pop3_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p++ = LF;

    *p++ = '.'; *p++ = CR; *p = LF;


    size += sizeof("STLS" CRLF) - 1;

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = ngx_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof("." CRLF) - 1));

    p = ngx_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;


    size = sizeof("+OK methods supported:" CRLF) - 1
           + sizeof("." CRLF) - 1;

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += ngx_mail_pop3_auth_methods_names[i].len
                    + sizeof(CRLF) - 1;
        }
    }

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->auth_capability.data = p;
    conf->auth_capability.len = size;

    p = ngx_cpymem(p, "+OK methods supported:" CRLF,
                   sizeof("+OK methods supported:" CRLF) - 1);

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            p = ngx_cpymem(p, ngx_mail_pop3_auth_methods_names[i].data,
                           ngx_mail_pop3_auth_methods_names[i].len);
            *p++ = CR; *p++ = LF;
        }
    }

    *p++ = '.'; *p++ = CR; *p = LF;


    p = ngx_pnalloc(cf->pool, stls_only_size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->starttls_only_capability.len = stls_only_size;
    conf->starttls_only_capability.data = p;

    p = ngx_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        if (ngx_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        p = ngx_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = ngx_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;

    return NGX_CONF_OK;
}
