
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


static void *ngx_imap_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_imap_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_imap_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_imap_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_imap_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_imap_core_capability(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_imap_core_procotol[] = {
    { ngx_string("pop3"), NGX_IMAP_POP3_PROTOCOL },
    { ngx_string("imap"), NGX_IMAP_IMAP_PROTOCOL },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_pop3_default_capabilities[] = {
    ngx_string("TOP"),
    ngx_string("USER"),
    ngx_string("UIDL"),
    ngx_null_string
};


static ngx_str_t  ngx_imap_default_capabilities[] = {
    ngx_string("IMAP4"),
    ngx_string("IMAP4rev1"),
    ngx_string("UIDPLUS"),
    ngx_null_string
};


static ngx_conf_bitmask_t  ngx_imap_auth_methods[] = {
    { ngx_string("plain"), NGX_IMAP_AUTH_PLAIN_ENABLED },
    { ngx_string("apop"), NGX_IMAP_AUTH_APOP_ENABLED },
    { ngx_string("cram-md5"), NGX_IMAP_AUTH_CRAM_MD5_ENABLED },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_pop3_auth_plain_capability =
    ngx_string("+OK methods supported:" CRLF
               "LOGIN" CRLF
               "PLAIN" CRLF
               "." CRLF);


static ngx_str_t  ngx_pop3_auth_cram_md5_capability =
    ngx_string("+OK methods supported:" CRLF
               "LOGIN" CRLF
               "PLAIN" CRLF
               "CRAM-MD5" CRLF
               "." CRLF);



static ngx_command_t  ngx_imap_core_commands[] = {

    { ngx_string("server"),
      NGX_IMAP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_imap_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_IMAP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_imap_core_listen,
      0,
      0,
      NULL },

    { ngx_string("protocol"),
      NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, protocol),
      &ngx_imap_core_procotol },

    { ngx_string("imap_client_buffer"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, imap_client_buffer_size),
      NULL },

    { ngx_string("so_keepalive"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, so_keepalive),
      NULL },

    { ngx_string("timeout"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("pop3_capabilities"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_1MORE,
      ngx_imap_core_capability,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, pop3_capabilities),
      NULL },

    { ngx_string("imap_capabilities"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_1MORE,
      ngx_imap_core_capability,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, imap_capabilities),
      NULL },

    { ngx_string("server_name"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, server_name),
      NULL },

    { ngx_string("auth"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_core_srv_conf_t, auth_methods),
      &ngx_imap_auth_methods },

      ngx_null_command
};


static ngx_imap_module_t  ngx_imap_core_module_ctx = {
    ngx_imap_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_imap_core_create_srv_conf,         /* create server configuration */
    ngx_imap_core_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_imap_core_module = {
    NGX_MODULE_V1,
    &ngx_imap_core_module_ctx,             /* module context */
    ngx_imap_core_commands,                /* module directives */
    NGX_IMAP_MODULE,                       /* module type */
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
ngx_imap_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_imap_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_imap_core_main_conf_t));
    if (cmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_imap_core_srv_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_imap_listen_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return cmcf;
}


static void *
ngx_imap_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_imap_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_imap_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    cscf->imap_client_buffer_size = NGX_CONF_UNSET_SIZE;
    cscf->protocol = NGX_CONF_UNSET_UINT;
    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;

    if (ngx_array_init(&cscf->pop3_capabilities, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cscf->imap_capabilities, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    return cscf;
}


static char *
ngx_imap_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_imap_core_srv_conf_t *prev = parent;
    ngx_imap_core_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size;
    ngx_str_t   *c, *d;
    ngx_uint_t   i;

    ngx_conf_merge_size_value(conf->imap_client_buffer_size,
                              prev->imap_client_buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_uint_value(conf->protocol, prev->protocol,
                              NGX_IMAP_IMAP_PROTOCOL);
    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);


    ngx_conf_merge_bitmask_value(conf->auth_methods, prev->auth_methods,
                           (NGX_CONF_BITMASK_SET|NGX_IMAP_AUTH_PLAIN_ENABLED));


    ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name.data = ngx_palloc(cf->pool, NGX_MAXHOSTNAMELEN);
        if (conf->server_name.data == NULL) {
            return NGX_CONF_ERROR;
        }

        if (gethostname((char *) conf->server_name.data, NGX_MAXHOSTNAMELEN)
            == -1)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "gethostname() failed");
            return NGX_CONF_ERROR;
        }

        conf->server_name.len = ngx_strlen(conf->server_name.data);
    }


    if (conf->pop3_capabilities.nelts == 0) {
        conf->pop3_capabilities = prev->pop3_capabilities;
    }

    if (conf->pop3_capabilities.nelts == 0) {

        for (d = ngx_pop3_default_capabilities; d->len; d++) {
            c = ngx_array_push(&conf->pop3_capabilities);
            if (c == NULL) {
                return NGX_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("+OK Capability list follows" CRLF) - 1
           + sizeof("." CRLF) - 1;

    c = conf->pop3_capabilities.elts;
    for (i = 0; i < conf->pop3_capabilities.nelts; i++) {
        size += c[i].len + sizeof(CRLF) - 1;
    }

    if (conf->auth_methods & NGX_IMAP_AUTH_CRAM_MD5_ENABLED) {
        size += sizeof("SASL LOGIN PLAIN CRAM-MD5" CRLF) - 1;

    } else {
        size += sizeof("SASL LOGIN PLAIN" CRLF) - 1;
    }

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->pop3_capability.len = size;
    conf->pop3_capability.data = p;

    p = ngx_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->pop3_capabilities.nelts; i++) {
        p = ngx_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    if (conf->auth_methods & NGX_IMAP_AUTH_CRAM_MD5_ENABLED) {
        p = ngx_cpymem(p, "SASL LOGIN PLAIN CRAM-MD5" CRLF,
                       sizeof("SASL LOGIN PLAIN CRAM-MD5" CRLF) - 1);

    } else {
        p = ngx_cpymem(p, "SASL LOGIN PLAIN" CRLF,
                       sizeof("SASL LOGIN PLAIN" CRLF) - 1);
    }

    *p++ = '.'; *p++ = CR; *p = LF;


    size += sizeof("STLS" CRLF) - 1;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->pop3_starttls_capability.len = size;
    conf->pop3_starttls_capability.data = p;

    p = ngx_cpymem(p, conf->pop3_capability.data,
                   conf->pop3_capability.len - (sizeof("." CRLF) - 1));

    p = ngx_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;


    if (conf->auth_methods & NGX_IMAP_AUTH_CRAM_MD5_ENABLED) {
        conf->pop3_auth_capability = ngx_pop3_auth_cram_md5_capability;

    } else {
        conf->pop3_auth_capability = ngx_pop3_auth_plain_capability;
    }


    if (conf->imap_capabilities.nelts == 0) {
        conf->imap_capabilities = prev->imap_capabilities;
    }

    if (conf->imap_capabilities.nelts == 0) {

        for (d = ngx_imap_default_capabilities; d->len; d++) {
            c = ngx_array_push(&conf->imap_capabilities);
            if (c == NULL) {
                return NGX_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("* CAPABILITY") - 1 + sizeof(CRLF) - 1;

    c = conf->imap_capabilities.elts;
    for (i = 0; i < conf->imap_capabilities.nelts; i++) {
        size += 1 + c[i].len;
    }

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->imap_capability.len = size;
    conf->imap_capability.data = p;

    p = ngx_cpymem(p, "* CAPABILITY", sizeof("* CAPABILITY") - 1);

    for (i = 0; i < conf->imap_capabilities.nelts; i++) {
        *p++ = ' ';
        p = ngx_cpymem(p, c[i].data, c[i].len);
    }

    *p++ = CR; *p = LF;


    size += sizeof(" STARTTLS") - 1;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->imap_starttls_capability.len = size;
    conf->imap_starttls_capability.data = p;

    p = ngx_cpymem(p, conf->imap_capability.data,
                   conf->imap_capability.len - (sizeof(CRLF) - 1));
    p = ngx_cpymem(p, " STARTTLS", sizeof(" STARTTLS") - 1);
    *p++ = CR; *p = LF;


    size += sizeof(" LOGINDISABLED") - 1;

    p = ngx_palloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->imap_starttls_only_capability.len = size;
    conf->imap_starttls_only_capability.data = p;

    p = ngx_cpymem(p, conf->imap_starttls_capability.data,
                   conf->imap_starttls_capability.len - (sizeof(CRLF) - 1));
    p = ngx_cpymem(p, " LOGINDISABLED", sizeof(" LOGINDISABLED") - 1);
    *p++ = CR; *p = LF;


    return NGX_CONF_OK;
}


static char *
ngx_imap_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_imap_module_t          *module;
    ngx_imap_conf_ctx_t        *ctx, *imap_ctx;
    ngx_imap_core_srv_conf_t   *cscf, **cscfp;
    ngx_imap_core_main_conf_t  *cmcf;


    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_imap_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    imap_ctx = cf->ctx;
    ctx->main_conf = imap_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_imap_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_IMAP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_imap_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_imap_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_IMAP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


/* AF_INET only */

static char *
ngx_imap_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i;
    ngx_imap_listen_t          *imls;
    ngx_imap_core_main_conf_t  *cmcf;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_imap_conf_get_module_main_conf(cf, ngx_imap_core_module);

    imls = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        if (imls[i].addr != u.addr.in_addr || imls[i].port != u.portn) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    imls = ngx_array_push(&cmcf->listen);
    if (imls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(imls, sizeof(ngx_imap_listen_t));

    imls->addr = u.addr.in_addr;
    imls->port = u.portn;
    imls->family = AF_INET;
    imls->ctx = cf->ctx;

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[2].data, "bind") == 0) {
        imls->bind = 1;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "the invalid \"%V\" parameter", &value[2]);
    return NGX_CONF_ERROR;
}


static char *
ngx_imap_core_capability(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t    *c, *value;
    ngx_uint_t    i;
    ngx_array_t  *a;

    a = (ngx_array_t *) (p + cmd->offset);

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        c = ngx_array_push(a);
        if (c == NULL) {
            return NGX_CONF_ERROR;
        }

        *c = value[i];
    }

    return NGX_CONF_OK;
}
