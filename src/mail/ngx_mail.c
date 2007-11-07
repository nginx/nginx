
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>


static char *ngx_mail_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static int ngx_mail_cmp_conf_in_addrs(const void *one, const void *two);


ngx_uint_t  ngx_mail_max_module;


static ngx_command_t  ngx_mail_commands[] = {

    { ngx_string("mail"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_mail_block,
      0,
      0,
      NULL },

    { ngx_string("imap"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_mail_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_mail_module_ctx = {
    ngx_string("mail"),
    NULL,
    NULL
};


ngx_module_t  ngx_mail_module = {
    NGX_MODULE_V1,
    &ngx_mail_module_ctx,                  /* module context */
    ngx_mail_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_mail_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    u_char                      *text;
    size_t                       len;
    ngx_uint_t                   i, a, l, m, mi, s, p, last, bind_all, done;
    ngx_conf_t                   pcf;
    ngx_array_t                  in_ports;
    ngx_listening_t             *ls;
    ngx_mail_listen_t           *imls;
    ngx_mail_module_t           *module;
    ngx_mail_in_port_t          *imip;
    ngx_mail_conf_ctx_t         *ctx;
    ngx_mail_conf_in_port_t     *in_port;
    ngx_mail_conf_in_addr_t     *in_addr;
    ngx_mail_core_srv_conf_t   **cscfp;
    ngx_mail_core_main_conf_t   *cmcf;

    if (cmd->name.data[0] == 'i') {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the \"imap\" directive is deprecated, "
                           "use the \"mail\" directive instead");
    }

    /* the main mail context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_mail_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_mail_conf_ctx_t **) conf = ctx;

    /* count the number of the http modules and set up their indices */

    ngx_mail_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_MAIL_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_mail_max_module++;
    }


    /* the mail main_conf context, it is the same in the all mail contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_mail_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the mail null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_mail_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all mail modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_MAIL_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the mail{} block */

    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NGX_MAIL_MODULE;
    cf->cmd_type = NGX_MAIL_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init mail{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_mail_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_MAIL_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init mail{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    *cf = pcf;


    if (ngx_array_init(&in_ports, cf->temp_pool, 4,
                       sizeof(ngx_mail_conf_in_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    imls = cmcf->listen.elts;

    for (l = 0; l < cmcf->listen.nelts; l++) {

        /* AF_INET only */

        in_port = in_ports.elts;
        for (p = 0; p < in_ports.nelts; p++) {
            if (in_port[p].port == imls[l].port) {
                in_port = &in_port[p];
                goto found;
            }
        }

        in_port = ngx_array_push(&in_ports);
        if (in_port == NULL) {
            return NGX_CONF_ERROR;
        }

        in_port->port = imls[l].port;

        if (ngx_array_init(&in_port->addrs, cf->temp_pool, 2,
                           sizeof(ngx_mail_conf_in_addr_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

    found:

        in_addr = ngx_array_push(&in_port->addrs);
        if (in_addr == NULL) {
            return NGX_CONF_ERROR;
        }

        in_addr->addr = imls[l].addr;
        in_addr->ctx = imls[l].ctx;
        in_addr->bind = imls[l].bind;
    }

    /* optimize the lists of ports and addresses */

    /* AF_INET only */

    in_port = in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {

        ngx_sort(in_port[p].addrs.elts, (size_t) in_port[p].addrs.nelts,
                 sizeof(ngx_mail_conf_in_addr_t), ngx_mail_cmp_conf_in_addrs);

        in_addr = in_port[p].addrs.elts;
        last = in_port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (in_addr[last - 1].addr == INADDR_ANY) {
            in_addr[last - 1].bind = 1;
            bind_all = 0;

        } else {
            bind_all = 1;
        }

        for (a = 0; a < last; /* void */ ) {

            if (!bind_all && !in_addr[a].bind) {
                a++;
                continue;
            }

            ls = ngx_listening_inet_stream_socket(cf, in_addr[a].addr,
                                                  in_port[p].port);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->backlog = NGX_LISTEN_BACKLOG;
            ls->rcvbuf = -1;
            ls->sndbuf = -1;

            ls->addr_ntop = 1;
            ls->handler = ngx_mail_init_connection;
            ls->pool_size = 256;

            /* STUB */
            ls->log = *cf->cycle->new_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;
            /**/

            imip = ngx_palloc(cf->pool, sizeof(ngx_mail_in_port_t));
            if (imip == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = imip;

            in_addr = in_port[p].addrs.elts;

            if (in_addr[a].bind && in_addr[a].addr != INADDR_ANY) {
                imip->naddrs = 1;
                done = 0;

            } else if (in_port[p].addrs.nelts > 1
                       && in_addr[last - 1].addr == INADDR_ANY)
            {
                imip->naddrs = last;
                done = 1;

            } else {
                imip->naddrs = 1;
                done = 0;
            }

#if 0
            ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
                          "%ui: %V %d %ui %ui",
                          a, &ls->addr_text, in_addr[a].bind,
                          imip->naddrs, last);
#endif

            imip->addrs = ngx_pcalloc(cf->pool,
                                    imip->naddrs * sizeof(ngx_mail_in_addr_t));
            if (imip->addrs == NULL) {
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < imip->naddrs; i++) {
                imip->addrs[i].addr = in_addr[i].addr;
                imip->addrs[i].ctx = in_addr[i].ctx;

                text = ngx_palloc(cf->pool,
                                  INET_ADDRSTRLEN - 1 + sizeof(":65535") - 1);
                if (text == NULL) {
                    return NGX_CONF_ERROR;
                }

                len = ngx_inet_ntop(AF_INET, &in_addr[i].addr, text,
                                    INET_ADDRSTRLEN);

                len = ngx_sprintf(text + len, ":%d", in_port[p].port) - text;

                imip->addrs[i].addr_text.len = len;
                imip->addrs[i].addr_text.data = text;
            }

            if (done) {
                break;
            }

            in_addr++;
            in_port[p].addrs.elts = in_addr;
            last--;

            a = 0;
        }
    }

    return NGX_CONF_OK;
}


static int
ngx_mail_cmp_conf_in_addrs(const void *one, const void *two)
{
    ngx_mail_conf_in_addr_t  *first, *second;

    first = (ngx_mail_conf_in_addr_t *) one;
    second = (ngx_mail_conf_in_addr_t *) two;

    if (first->addr == INADDR_ANY) {
        /* the INADDR_ANY must be the last resort, shift it to the end */
        return 1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
