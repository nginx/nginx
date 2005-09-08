
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


static ngx_command_t  ngx_imap_core_commands[] = {

    { ngx_string("server"),
      NGX_IMAP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_imap_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
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
                       sizeof(ngx_imap_core_srv_conf_t *)) == NGX_ERROR)
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
    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->protocol = NGX_CONF_UNSET_UINT;

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

    size_t       size;
    ngx_buf_t   *b;
    ngx_str_t   *c, *d;
    ngx_uint_t   i;

    ngx_conf_merge_size_value(conf->imap_client_buffer_size,
                              prev->imap_client_buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_unsigned_value(conf->protocol, prev->protocol,
                              NGX_IMAP_IMAP_PROTOCOL);


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

    b = ngx_create_temp_buf(cf->pool, size);
    if (b == NULL) {
        return NGX_CONF_ERROR;
    }

    b->last = ngx_cpymem(b->last, "+OK Capability list follows" CRLF,
                         sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->pop3_capabilities.nelts; i++) {
        b->last = ngx_cpymem(b->last, c[i].data, c[i].len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = '.'; *b->last++ = CR; *b->last++ = LF;

    conf->pop3_capability = b;


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

    b = ngx_create_temp_buf(cf->pool, size);
    if (b == NULL) {
        return NGX_CONF_ERROR;
    }

    b->last = ngx_cpymem(b->last, "* CAPABILITY", sizeof("* CAPABILITY") - 1);

    for (i = 0; i < conf->imap_capabilities.nelts; i++) {
        *b->last++ = ' ';
        b->last = ngx_cpymem(b->last, c[i].data, c[i].len);
    }

    *b->last++ = CR; *b->last++ = LF;

    conf->imap_capability = b;

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
    char                 *err;
    ngx_str_t            *value;
    in_addr_t             in_addr;
    struct hostent       *h;
    ngx_listening_t      *ls;
    ngx_inet_upstream_t   inet_upstream;

    value = cf->args->elts;

    ngx_memzero(&inet_upstream, sizeof(ngx_inet_upstream_t));

    inet_upstream.url = value[1];
    inet_upstream.port_only = 1;

    err = ngx_inet_parse_host_port(&inet_upstream);

    if (err) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s in \"%V\" of the \"listen\" directive",
                           err, &inet_upstream.url);
        return NGX_CONF_ERROR;
    }

    if (inet_upstream.host.len) {
        inet_upstream.host.data[inet_upstream.host.len] = '\0';

        in_addr = inet_addr((const char *) inet_upstream.host.data);

        if (in_addr == INADDR_NONE) {
            h = gethostbyname((const char *) inet_upstream.host.data);
    
            if (h == NULL || h->h_addr_list[0] == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "can not resolve host \"%s\" "
                                   "in the \"listen\" directive",
                                   inet_upstream.host.data);
                return NGX_CONF_ERROR;
            }

            in_addr = *(in_addr_t *)(h->h_addr_list[0]);
        }

    } else {
        in_addr = INADDR_ANY;
    }


    ls = ngx_listening_inet_stream_socket(cf, in_addr, inet_upstream.port);
    if (ls == NULL) {
        return NGX_CONF_ERROR; 
    }

    ls->backlog = -1;
    ls->addr_ntop = 1;
    ls->handler = ngx_imap_init_connection;
    ls->pool_size = 256;

    ls->ctx = cf->ctx;

    /* STUB */
    ls->log = cf->cycle->new_log;
    /**/

    return NGX_CONF_OK;
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
