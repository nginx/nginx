
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>


static void *ngx_mail_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_mail_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_mail_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_deprecated_t  ngx_conf_deprecated_so_keepalive = {
    ngx_conf_deprecated, "so_keepalive",
    "so_keepalive\" parameter of the \"listen"
};


static ngx_command_t  ngx_mail_core_commands[] = {

    { ngx_string("server"),
      NGX_MAIL_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_mail_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_core_listen,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("protocol"),
      NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_mail_core_protocol,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("so_keepalive"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_core_srv_conf_t, so_keepalive),
      &ngx_conf_deprecated_so_keepalive },

    { ngx_string("timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("server_name"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_core_srv_conf_t, server_name),
      NULL },

    { ngx_string("error_log"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_core_error_log,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_core_resolver,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_core_srv_conf_t, resolver_timeout),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_core_module_ctx = {
    NULL,                                  /* protocol */

    ngx_mail_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_core_create_srv_conf,         /* create server configuration */
    ngx_mail_core_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_mail_core_module = {
    NGX_MODULE_V1,
    &ngx_mail_core_module_ctx,             /* module context */
    ngx_mail_core_commands,                /* module directives */
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
ngx_mail_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_mail_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_mail_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_mail_listen_t))
        != NGX_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
ngx_mail_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->protocol = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;

    cscf->resolver = NGX_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
ngx_mail_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_core_srv_conf_t *prev = parent;
    ngx_mail_core_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
                              30000);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);


    ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    if (conf->protocol == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown mail protocol for server in %s:%ui",
                      conf->file_name, conf->line);
        return NGX_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    return NGX_CONF_OK;
}


static char *
ngx_mail_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_mail_module_t          *module;
    ngx_mail_conf_ctx_t        *ctx, *mail_ctx;
    ngx_mail_core_srv_conf_t   *cscf, **cscfp;
    ngx_mail_core_main_conf_t  *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_mail_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    mail_ctx = cf->ctx;
    ctx->main_conf = mail_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_mail_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_MAIL_MODULE) {
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

    cscf = ctx->srv_conf[ngx_mail_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_mail_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_MAIL_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_mail_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_core_srv_conf_t  *cscf = conf;

    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i, m;
    struct sockaddr            *sa;
    ngx_mail_listen_t          *ls;
    ngx_mail_module_t          *module;
    struct sockaddr_in         *sin;
    ngx_mail_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_mail_conf_get_module_main_conf(cf, ngx_mail_core_module);

    ls = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) ls[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = (struct sockaddr_in6 *) sa;
            port = ntohs(sin6->sin6_port);
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            off = offsetof(struct sockaddr_un, sun_path);
            len = sizeof(((struct sockaddr_un *) sa)->sun_path);
            port = 0;
            break;
#endif

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = (struct sockaddr_in *) sa;
            port = ntohs(sin->sin_port);
            break;
        }

        if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_mail_listen_t));

    ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = 1;
#endif

    if (cscf->protocol == NULL) {
        for (m = 0; ngx_modules[m]; m++) {
            if (ngx_modules[m]->type != NGX_MAIL_MODULE) {
                continue;
            }

            module = ngx_modules[m]->ctx;

            if (module->protocol == NULL) {
                continue;
            }

            for (i = 0; module->protocol->port[i]; i++) {
                if (module->protocol->port[i] == u.port) {
                    cscf->protocol = module->protocol;
                    break;
                }
            }
        }
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) ls->sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, ls->socklen, buf,
                                    NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_MAIL_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_mail_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
                    && ls->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_mail_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_core_srv_conf_t  *cscf = conf;

    ngx_str_t          *value;
    ngx_uint_t          m;
    ngx_mail_module_t  *module;

    value = cf->args->elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_MAIL_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->protocol
            && ngx_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;

            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_mail_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_core_srv_conf_t  *cscf = conf;

    return ngx_log_set_log(cf, &cscf->error_log);
}


static char *
ngx_mail_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_core_srv_conf_t  *cscf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (cscf->resolver != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NULL;
        return NGX_CONF_OK;
    }

    cscf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_mail_capabilities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
