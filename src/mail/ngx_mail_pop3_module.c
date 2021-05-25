
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

static ngx_str_t default_pop3_greeting = ngx_string("+OK POP3 ready");

static ngx_str_t  ngx_mail_pop3_default_capabilities[] = {
    ngx_string("TOP"),
    ngx_string("USER"),
    ngx_string("UIDL"),
    ngx_null_string
};


static ngx_conf_bitmask_t  ngx_mail_pop3_auth_methods[] = {
    { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
    { ngx_string("apop"), NGX_MAIL_AUTH_APOP_ENABLED },
    { ngx_string("login"), NGX_MAIL_AUTH_LOGIN_ENABLED },
    { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
    { ngx_string("gssapi"), NGX_MAIL_AUTH_GSSAPI_ENABLED },
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


static ngx_str_t  ngx_mail_pop3_auth_plain_capability =
    ngx_string("+OK methods supported:" CRLF
               "LOGIN" CRLF
               "PLAIN" CRLF
               "." CRLF);


static ngx_str_t  ngx_mail_pop3_auth_cram_md5_capability =
    ngx_string("+OK methods supported:" CRLF
               "LOGIN" CRLF
               "PLAIN" CRLF
               "CRAM-MD5" CRLF
               "." CRLF);


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
    ngx_string("-ERR No required SSL certificate" CRLF),
    ngx_string("")
};


static ngx_command_t  ngx_mail_pop3_commands[] = {

    { ngx_string("pop3_client_buffer"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_pop3_srv_conf_t, client_buffer_size),
      NULL },

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

    { ngx_string("pop3_greeting"),
      NGX_MAIL_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_pop3_srv_conf_t, greeting),
      NULL },

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

    pscf->client_buffer_size = NGX_CONF_UNSET_SIZE;

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

    u_char      *p, *p1, *p2, *p3;
    size_t       s1, s2, s3;
    ngx_str_t   *c, *d;
    ngx_uint_t   i;

    ngx_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) 4*ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->auth_methods,
                                 prev->auth_methods,
                                 NGX_CONF_BITMASK_SET);

    /*
    if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
        conf->auth_methods |= NGX_MAIL_AUTH_LOGIN_ENABLED;
    }
    */

    ngx_conf_merge_str_value(conf->greeting, prev->greeting,"");

    if (conf->greeting.len == 0) {
        conf->greeting = default_pop3_greeting;
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

    s1 = sizeof("+OK Capability list follows" CRLF) - 1
         + sizeof("." CRLF)-1;
    if (conf->auth_methods &
        (NGX_MAIL_AUTH_PLAIN_ENABLED | NGX_MAIL_AUTH_GSSAPI_ENABLED))
         s1 += sizeof("SASL" CRLF)-1;
    s2 = s1;
    s3 = s1;

    c = conf->capabilities.elts;
    for (i=0; i<conf->capabilities.nelts; ++i)
    {
        s1 += c[i].len + sizeof (CRLF)-1;
        s2 += c[i].len + sizeof (CRLF)-1;
        if (ngx_strcasecmp(c[i].data, (u_char *) "USER") != 0) {
            s3 += c[i].len + sizeof (CRLF)-1;
        }
    }

    if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
        s1 += sizeof(" PLAIN") - 1;
        s2 += sizeof(" PLAIN") - 1;
        s3 += sizeof(" PLAIN") - 1;
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED) {
        s1 += sizeof(" GSSAPI") - 1;
        s2 += sizeof(" GSSAPI") - 1;
        s3 += sizeof(" GSSAPI") - 1;
    }

    s2 += sizeof("STLS" CRLF) - 1;
    s3 += sizeof("STLS" CRLF) - 1;

    p1 = ngx_pnalloc(cf->pool,s1);
    if (p1 == NULL) {
        return NGX_CONF_ERROR;
    }
    p2 = ngx_palloc(cf->pool,s2);
    if (p2 == NULL) {
        return NGX_CONF_ERROR;
    }
    p3 = ngx_pnalloc(cf->pool,s3);
    if (p3 == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->capability.len = s1;
    conf->capability.data = p1;
    conf->starttls_capability.len = s2;
    conf->starttls_capability.data = p2;
    conf->starttls_only_capability.len = s3;
    conf->starttls_only_capability.data = p3;

    p1 = ngx_cpymem(p1, "+OK Capability list follows" CRLF,
                        sizeof("+OK Capability list follows" CRLF) - 1);
    p2 = ngx_cpymem(p2, "+OK Capability list follows" CRLF,
                        sizeof("+OK Capability list follows" CRLF) - 1);
    p3 = ngx_cpymem(p3, "+OK Capability list follows" CRLF,
                        sizeof("+OK Capability list follows" CRLF) - 1);

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; ++i)
    {
        p1 = ngx_cpymem(p1,c[i].data,c[i].len);
        p2 = ngx_cpymem(p2,c[i].data,c[i].len);
        *p1++ = CR; *p1++ = LF;
        *p2++ = CR; *p2++ = LF;
        if (ngx_strcasecmp(c[i].data, (u_char *) "USER") != 0) {
            p3 = ngx_cpymem(p3,c[i].data,c[i].len);
            *p3++ = CR; *p3++ = LF;
        }
    }

    if (conf->auth_methods &
        (NGX_MAIL_AUTH_PLAIN_ENABLED | NGX_MAIL_AUTH_GSSAPI_ENABLED)) {
        p1 = ngx_cpymem(p1,"SASL",sizeof("SASL") - 1);
        p2 = ngx_cpymem(p2,"SASL",sizeof("SASL") - 1);
        p3 = ngx_cpymem(p3,"SASL",sizeof("SASL") - 1);

        if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
            p1 = ngx_cpymem(p1," PLAIN",sizeof(" PLAIN") - 1);
            p2 = ngx_cpymem(p2," PLAIN",sizeof(" PLAIN") - 1);
            p3 = ngx_cpymem(p3," PLAIN",sizeof(" PLAIN") - 1);
        }
        if (conf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED) {
            p1 = ngx_cpymem(p1," GSSAPI",sizeof(" GSSAPI") - 1);
            p2 = ngx_cpymem(p2," GSSAPI",sizeof(" GSSAPI") - 1);
            p3 = ngx_cpymem(p3," GSSAPI",sizeof(" GSSAPI") - 1);
        }

        *p1++ = CR; *p1++ = LF;
        *p2++ = CR; *p2++ = LF;
        *p3++ = CR; *p3++ = LF;
    }

    p2 = ngx_cpymem(p2,"STLS" CRLF, sizeof("STLS" CRLF)-1);
    p3 = ngx_cpymem(p3,"STLS" CRLF, sizeof("STLS" CRLF)-1);

    *p1++ = '.'; *p1++ = CR; *p1++ = LF;
    *p2++ = '.'; *p2++ = CR; *p2++ = LF;
    *p3++ = '.'; *p3++ = CR; *p3++ = LF;

    /* not required */
    if (conf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED) {
        conf->auth_capability = ngx_mail_pop3_auth_cram_md5_capability;

    } else {
        conf->auth_capability = ngx_mail_pop3_auth_plain_capability;
    }

    p = ngx_pnalloc(cf->pool,conf->greeting.len + 2);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(p, conf->greeting.data, conf->greeting.len);
    ngx_memcpy(p + conf->greeting.len, CRLF, sizeof(CRLF) - 1);
    conf->greeting.data = p;
    conf->greeting.len += 2;

    return NGX_CONF_OK;
}
