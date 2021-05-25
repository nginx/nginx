
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_imap_module.h>


static void *ngx_mail_imap_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_imap_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_mail_imap_id (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_str_t default_imap_greeting = ngx_string("* OK IMAP4rev1 proxy server ready");

static ngx_str_t  ngx_mail_imap_default_capabilities[] = {
    ngx_string("IMAP4"),
    ngx_string("IMAP4rev1"),
    ngx_string("UIDPLUS"),
    ngx_null_string
};


static ngx_conf_bitmask_t  ngx_mail_imap_auth_methods[] = {
    { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
    { ngx_string("login"), NGX_MAIL_AUTH_LOGIN_ENABLED },
    { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
    { ngx_string("external"), NGX_MAIL_AUTH_EXTERNAL_ENABLED },
    { ngx_string("gssapi"), NGX_MAIL_AUTH_GSSAPI_ENABLED },
    { ngx_null_string, 0 }
};


/* zimbra's merge_conf method doesn't use this
static ngx_str_t  ngx_mail_imap_auth_methods_names[] = {
    ngx_string("AUTH=PLAIN"),
    ngx_string("AUTH=LOGIN"),
    ngx_null_string,  // APOP
    ngx_string("AUTH=CRAM-MD5"),
    ngx_string("AUTH=EXTERNAL"),
    ngx_null_string   // NONE
};*/


static ngx_mail_protocol_t  ngx_mail_imap_protocol = {
    ngx_string("imap"),
    { 143, 993, 0, 0 },
    NGX_MAIL_IMAP_PROTOCOL,

    ngx_mail_imap_init_session,
    ngx_mail_imap_init_protocol,
    ngx_mail_imap_parse_command,
    ngx_mail_imap_auth_state,

    ngx_string("* BAD internal server error" CRLF),
    ngx_string("* BYE SSL certificate error" CRLF),
    ngx_string("* BYE No required SSL certificate" CRLF),
    ngx_string("* BYE IMAP server terminating connection" CRLF)
};


static ngx_command_t  ngx_mail_imap_commands[] = {

    { ngx_string("imap_client_buffer"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_imap_srv_conf_t, client_buffer_size),
      NULL },

    { ngx_string("imap_capabilities"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_capabilities,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_imap_srv_conf_t, capabilities),
      NULL },

    { ngx_string("imap_id"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_imap_id,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_imap_srv_conf_t, id_params),
      NULL },

    { ngx_string("imap_auth"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_imap_srv_conf_t, auth_methods),
      &ngx_mail_imap_auth_methods },

    { ngx_string("imap_literalauth"),
      NGX_MAIL_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_imap_srv_conf_t, literalauth),
      NULL },

    { ngx_string("imap_greeting"),
      NGX_MAIL_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_imap_srv_conf_t, greeting),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_imap_module_ctx = {
    &ngx_mail_imap_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_imap_create_srv_conf,         /* create server configuration */
    ngx_mail_imap_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_mail_imap_module = {
    NGX_MODULE_V1,
    &ngx_mail_imap_module_ctx,             /* module context */
    ngx_mail_imap_commands,                /* module directives */
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
ngx_mail_imap_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_imap_srv_conf_t  *iscf;

    iscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_imap_srv_conf_t));
    if (iscf == NULL) {
        return NULL;
    }

    iscf->client_buffer_size = NGX_CONF_UNSET_SIZE;

    if (ngx_array_init(&iscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&iscf->id_params, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    iscf->literalauth = NGX_CONF_UNSET;

    ngx_str_null(&iscf->ua_name);
    ngx_str_null(&iscf->ua_version);

    return iscf;
}


static char *
ngx_mail_imap_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_imap_srv_conf_t *prev = parent;
    ngx_mail_imap_srv_conf_t *conf = child;

    u_char      *p, *p1, *p2, *p3;
    size_t      size, s1, s2, s3;
    ngx_str_t   *c, *d;
    ngx_uint_t   i;

    ngx_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) 4 * ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (NGX_CONF_BITMASK_SET
                               |NGX_MAIL_AUTH_PLAIN_ENABLED));

    if (conf->id_params.nelts == 0) {
        conf->id_params = prev->id_params;
    }

    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = ngx_mail_imap_default_capabilities; d->len; d++) {
            c = ngx_array_push(&conf->capabilities);
            if (c == NULL) {
                return NGX_CONF_ERROR;
            }

            *c = *d;
        }
    }

    s1 = sizeof("* CAPABILITY" CRLF) - 1;
    s2 = s1;
    s3 = s1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        s1 += 1 + c[i].len;
        s2 += 1 + c[i].len;
        s3 += 1 + c[i].len;
    }

    if (conf->auth_methods & NGX_MAIL_AUTH_LOGIN_ENABLED) {
        s1 += sizeof (" AUTH=LOGIN") - 1;
        s2 += sizeof (" AUTH=LOGIN") - 1;
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
        s1 += sizeof (" AUTH=PLAIN") - 1;
        s2 += sizeof (" AUTH=PLAIN") - 1;
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED) {
        s1 += sizeof (" AUTH=CRAM-MD5") - 1;
        s2 += sizeof (" AUTH=CRAM-MD5") - 1;
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED) {
        s1 += sizeof (" AUTH=GSSAPI") - 1;
        s2 += sizeof (" AUTH=GSSAPI") - 1;
        s3 += sizeof (" AUTH=GSSAPI") - 1;
    }

    s2 += sizeof (" STARTTLS") - 1;
    s3 += sizeof (" STARTTLS") - 1;
    s3 += sizeof (" LOGINDISABLED") - 1;

    p1 = ngx_palloc(cf->pool, s1);
    if (p1 == NULL) {
        return NGX_CONF_ERROR;
    }
    p2 = ngx_palloc(cf->pool, s2);
    if (p2 == NULL) {
        return NGX_CONF_ERROR;
    }
    p3 = ngx_palloc(cf->pool, s3);
    if (p3 == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->capability.len = s1;
    conf->capability.data = p1;

    conf->starttls_capability.len = s2;
    conf->starttls_capability.data = p2;

    conf->starttls_only_capability.len = s3;
    conf->starttls_only_capability.data = p3;

    p1 = ngx_cpymem(p1, "* CAPABILITY", sizeof("* CAPABILITY") - 1);
    p2 = ngx_cpymem(p2, "* CAPABILITY", sizeof("* CAPABILITY") - 1);
    p3 = ngx_cpymem(p3, "* CAPABILITY", sizeof("* CAPABILITY") - 1);

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        *p1++ = ' ';
        p1 = ngx_cpymem(p1,c[i].data,c[i].len);
        *p2++ = ' ';
        p2 = ngx_cpymem(p2,c[i].data,c[i].len);
        *p3++ = ' ';
        p3 = ngx_cpymem(p3,c[i].data,c[i].len);
    }

    if (conf->auth_methods & NGX_MAIL_AUTH_LOGIN_ENABLED) {
        p1 = ngx_cpymem(p1," AUTH=LOGIN", sizeof(" AUTH=LOGIN") - 1);
        p2 = ngx_cpymem(p2," AUTH=LOGIN", sizeof(" AUTH=LOGIN") - 1);
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
        p1 = ngx_cpymem(p1," AUTH=PLAIN", sizeof(" AUTH=PLAIN") - 1);
        p2 = ngx_cpymem(p2," AUTH=PLAIN", sizeof(" AUTH=PLAIN") - 1);
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED) {
        p1 = ngx_cpymem(p1," AUTH=CRAM-MD5", sizeof(" AUTH=CRAM-MD5") - 1);
        p2 = ngx_cpymem(p2," AUTH=CRAM-MD5", sizeof(" AUTH=CRAM-MD5") - 1);
    }
    if (conf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED) {
        p1 = ngx_cpymem(p1," AUTH=GSSAPI", sizeof(" AUTH=GSSAPI") - 1);
        p2 = ngx_cpymem(p2," AUTH=GSSAPI", sizeof(" AUTH=GSSAPI") - 1);
        p3 = ngx_cpymem(p3," AUTH=GSSAPI", sizeof(" AUTH=GSSAPI") - 1);
    }

    p2 = ngx_cpymem(p2," STARTTLS",sizeof(" STARTTLS")-1);
    p3 = ngx_cpymem(p3," STARTTLS",sizeof(" STARTTLS")-1);
    p3 = ngx_cpymem(p3," LOGINDISABLED",sizeof(" LOGINDISABLED")-1);

    *p1++ = CR; *p1++ = LF;
    *p2++ = CR; *p2++ = LF;
    *p3++ = CR; *p3++ = LF;

     ngx_conf_merge_str_value(conf->greeting, prev->greeting, "");
     if (conf->greeting.len == 0) {
        conf->greeting = default_imap_greeting;
     }

    p = ngx_pnalloc(cf->pool, conf->greeting.len + 2);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

     ngx_memcpy(p, conf->greeting.data, conf->greeting.len);
     ngx_memcpy(p + conf->greeting.len, CRLF, sizeof(CRLF)-1);
     conf->greeting.data = p;
     conf->greeting.len += 2;
     
    size = sizeof ("* ID ()" CRLF) - 1;

    c = conf->id_params.elts;
    for (i = 0; i < conf->id_params.nelts; ++i) {
        if (!((c[i].len == 3) &&
            (c[i].data[0] == 'n' || c[i].data[0] == 'N') &&
            (c[i].data[1] == 'i' || c[i].data[1] == 'I') &&
            (c[i].data[2] == 'l' || c[i].data[2] == 'L'))
           )
        {
            size += 2;      // for enclosing quotes
        }

        size += c[i].len;
        size += 1;          // for following SP
    }

    if (conf->id_params.nelts > 0) {
        --size;                 // no SP follows the last parameter
    } else {
        size = size - 2 + 3;    // take away the () and put nil
    }

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->id.len = size;
    conf->id.data = p;

    p = ngx_cpymem (p, "* ID ", sizeof ("* ID ") -1);

    if (conf->id_params.nelts > 0) 
    {
        *p++ = '(';
        
        for (i = 0; i < conf->id_params.nelts; ++i)
        {
            if (!((c[i].len == 3) &&
                (c[i].data[0] == 'n' || c[i].data[0] == 'N') &&
                (c[i].data[1] == 'i' || c[i].data[1] == 'I') &&
                (c[i].data[2] == 'l' || c[i].data[2] == 'L'))
               )
            {
                *p++ = '"';
                p = ngx_cpymem(p, c[i].data, c[i].len);
                *p++ = '"';
            }
            else
            {
                p = ngx_cpymem(p, c[i].data, c[i].len);
            }

            if (i < conf->id_params.nelts - 1)
                *p++ = ' ';
        }

        *p++ = ')';
    }
    else
    {
        p = ngx_cpymem (p, "nil", sizeof("nil") - 1);
    }

    *p++ = CR; *p = LF;
    ngx_conf_merge_value (conf->literalauth, prev->literalauth,1);
    ngx_conf_merge_str_value (conf->ua_name, prev->ua_name, "ZCS");
    ngx_conf_merge_str_value (conf->ua_version, prev->ua_version, "Unknown Version");
 
    return NGX_CONF_OK;
}

static char *
ngx_mail_imap_id (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;
    ngx_mail_imap_srv_conf_t  *iscf;
    ngx_str_t   *c, *value, *elt;
    ngx_uint_t  i;
    ngx_array_t *a;

    iscf = (ngx_mail_imap_srv_conf_t *)conf;

    value = cf->args->elts;

    if (cf->args->nelts % 2 == 0)
    {
        // ID response must contain id param field-value pairs
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
            "unmatched pair in IMAP ID string: %V",
            value + cf->args->nelts - 1);

        return NGX_CONF_ERROR;
    }
    else
    {
        a = (ngx_array_t *) (p + cmd->offset);
        for (i = 1; i < cf->args->nelts; ++i)
        {
            c = ngx_array_push (a);
            if (c == NULL) {
                return NGX_CONF_ERROR;
            }

            *c = value[i];
        }

        for (i = 0; i < a->nelts; i += 2 ) {
            elt = ((ngx_str_t *) a->elts + i);
            if (elt->len == sizeof ("NAME") - 1 &&
                (elt->data[0] == 'N' || elt->data[0] == 'n') &&
                (elt->data[1] == 'A' || elt->data[1] == 'a') &&
                (elt->data[2] == 'M' || elt->data[2] == 'm') &&
                (elt->data[3] == 'E' || elt->data[0] == 'e')) {
                iscf->ua_name = *(elt + 1);
            }else if (elt->len == sizeof ("VERSION") - 1 &&
                (elt->data[0] == 'V' || elt->data[0] == 'v') &&
                (elt->data[1] == 'E' || elt->data[1] == 'e') &&
                (elt->data[2] == 'R' || elt->data[2] == 'r') &&
                (elt->data[3] == 'S' || elt->data[3] == 's') &&
                (elt->data[4] == 'I' || elt->data[4] == 'i') &&
                (elt->data[5] == 'O' || elt->data[5] == 'o') &&
                (elt->data[6] == 'N' || elt->data[6] == 'n')) {
                iscf->ua_version = *(elt + 1);
            }
        }

        return NGX_CONF_OK;
    }
}

