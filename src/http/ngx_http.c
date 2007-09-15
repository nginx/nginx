
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
    ngx_http_conf_in_port_t *in_port, ngx_http_listen_t *lscf,
    ngx_http_core_srv_conf_t *cscf);
static ngx_int_t ngx_http_add_names(ngx_conf_t *cf,
    ngx_http_conf_in_addr_t *in_addr, ngx_http_core_srv_conf_t *cscf);
static char *ngx_http_merge_locations(ngx_conf_t *cf,
    ngx_array_t *locations, void **loc_conf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static int ngx_http_cmp_conf_in_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
    const void *two);

ngx_uint_t   ngx_http_max_module;

ngx_uint_t   ngx_http_total_requests;
uint64_t     ngx_http_total_sent;


ngx_int_t  (*ngx_http_top_header_filter) (ngx_http_request_t *r);
ngx_int_t  (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static ngx_command_t  ngx_http_commands[] = {

    { ngx_string("http"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_http_module_ctx = {
    ngx_string("http"),
    NULL,
    NULL
};


ngx_module_t  ngx_http_module = {
    NGX_MODULE_V1,
    &ngx_http_module_ctx,                  /* module context */
    ngx_http_commands,                     /* module directives */
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
ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_int_t                    rc, j;
    ngx_uint_t                   mi, m, s, l, p, a, i, n;
    ngx_uint_t                   find_config_index, use_rewrite, use_access;
    ngx_uint_t                   last, bind_all, done;
    ngx_conf_t                   pcf;
    ngx_array_t                  headers_in, in_ports;
    ngx_hash_key_t              *hk;
    ngx_hash_init_t              hash;
    ngx_listening_t             *ls;
    ngx_http_listen_t           *lscf;
    ngx_http_module_t           *module;
    ngx_http_header_t           *header;
    ngx_http_in_port_t          *hip;
    ngx_http_handler_pt         *h;
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_conf_in_port_t     *in_port;
    ngx_http_conf_in_addr_t     *in_addr;
    ngx_hash_keys_arrays_t       ha;
    ngx_http_server_name_t      *name;
    ngx_http_phase_handler_t    *ph;
    ngx_http_virtual_names_t    *vn;
    ngx_http_core_srv_conf_t   **cscfp, *cscf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_phase_handler_pt    checker;
    ngx_http_core_main_conf_t   *cmcf;
#if (NGX_PCRE)
    ngx_uint_t                   regex;
#endif
#if (NGX_WIN32)
    ngx_iocp_conf_t             *iocpcf;
#endif

    /* the main http context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_http_conf_ctx_t **) conf = ctx;


    /* count the number of the http modules and set up their indices */

    ngx_http_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_http_max_module++;
    }


    /* the http main_conf context, it is the same in the all http contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_http_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null loc_conf context, it is used to merge
     * the server{}s' loc_conf's
     */

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all http modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
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

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* parse inside the http{} block */

    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }

    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init http{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }

            if (module->merge_loc_conf) {

                /* merge the server{}'s loc_conf */

                rv = module->merge_loc_conf(cf,
                                            ctx->loc_conf[mi],
                                            cscfp[s]->ctx->loc_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }

                /* merge the locations{}' loc_conf's */

                rv = ngx_http_merge_locations(cf, &cscfp[s]->locations,
                                              cscfp[s]->ctx->loc_conf,
                                              module, mi);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }


    /* init lists of the handlers */

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (header = ngx_http_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (ngx_http_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * http{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

    *cf = pcf;


    cmcf->phase_engine.server_rewrite_index = (ngx_uint_t) -1;
    cmcf->phase_engine.location_rewrite_index = (ngx_uint_t) -1;
    find_config_index = 0;
    use_rewrite = cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    n = use_rewrite + use_access + 1; /* find config phase */

    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = ngx_pcalloc(cf->pool,
                     n * sizeof(ngx_http_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NGX_CONF_ERROR;
    }

    cmcf->phase_engine.handlers = ph;
    n = 0;

    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;

        switch (i) {

        case NGX_HTTP_SERVER_REWRITE_PHASE:
            if (cmcf->phase_engine.server_rewrite_index == (ngx_uint_t) -1) {
                cmcf->phase_engine.server_rewrite_index = n;
            }
            checker = ngx_http_core_generic_phase;

            break;

        case NGX_HTTP_FIND_CONFIG_PHASE:
            find_config_index = n;

            ph->checker = ngx_http_core_find_config_phase;
            n++;
            ph++;

            continue;

        case NGX_HTTP_REWRITE_PHASE:
            if (cmcf->phase_engine.location_rewrite_index == (ngx_uint_t) -1) {
                cmcf->phase_engine.location_rewrite_index = n;
            }
            checker = ngx_http_core_generic_phase;

            break;

        case NGX_HTTP_POST_REWRITE_PHASE:
            if (use_rewrite) {
                ph->checker = ngx_http_core_post_rewrite_phase;
                ph->next = find_config_index;
                n++;
                ph++;
            }

            continue;

        case NGX_HTTP_ACCESS_PHASE:
            checker = ngx_http_core_access_phase;
            n++;
            break;

        case NGX_HTTP_POST_ACCESS_PHASE:
            if (use_access) {
                ph->checker = ngx_http_core_post_access_phase;
                ph->next = n;
                ph++;
            }

            continue;

        case NGX_HTTP_CONTENT_PHASE:
            checker = ngx_http_core_content_phase;
            break;

        default:
            checker = ngx_http_core_generic_phase;
        }

        n += cmcf->phases[i].handlers.nelts;

        for (j = cmcf->phases[i].handlers.nelts - 1; j >=0; j--) {
            ph->checker = checker;
            ph->handler = h[j];
            ph->next = n;
            ph++;
        }
    }


    /*
     * create the lists of ports, addresses and server names
     * to quickly find the server core module configuration at run-time
     */

    if (ngx_array_init(&in_ports, cf->temp_pool, 2,
                       sizeof(ngx_http_conf_in_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* "server" directives */

    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {

        /* "listen" directives */

        lscf = cscfp[s]->listen.elts;
        for (l = 0; l < cscfp[s]->listen.nelts; l++) {

            /* AF_INET only */

            in_port = in_ports.elts;
            for (p = 0; p < in_ports.nelts; p++) {

                if (lscf[l].port != in_port[p].port) {
                    continue;
                }

                /* the port is already in the port list */

                in_addr = in_port[p].addrs.elts;
                for (a = 0; a < in_port[p].addrs.nelts; a++) {

                    if (lscf[l].addr != in_addr[a].addr) {
                        continue;
                    }

                    /* the address is already in the address list */

                    if (ngx_http_add_names(cf, &in_addr[a], cscfp[s]) != NGX_OK)
                    {
                        return NGX_CONF_ERROR;
                    }

                    /*
                     * check the duplicate "default" server
                     * for this address:port
                     */

                    if (lscf[l].conf.default_server) {

                        if (in_addr[a].default_server) {
                            ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                                      "the duplicate default server in %s:%ui",
                                       &lscf[l].file_name, lscf[l].line);

                            return NGX_CONF_ERROR;
                        }

                        in_addr[a].core_srv_conf = cscfp[s];
                        in_addr[a].default_server = 1;
                    }

                    goto found;
                }

                /*
                 * add the address to the addresses list that
                 * bound to this port
                 */

                if (ngx_http_add_address(cf, &in_port[p], &lscf[l], cscfp[s])
                    != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }

                goto found;
            }

            /* add the port to the in_port list */

            in_port = ngx_array_push(&in_ports);
            if (in_port == NULL) {
                return NGX_CONF_ERROR;
            }

            in_port->port = lscf[l].port;
            in_port->addrs.elts = NULL;

            if (ngx_http_add_address(cf, in_port, &lscf[l], cscfp[s]) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

        found:

            continue;
        }
    }


    /* optimize the lists of ports, addresses and server names */

    /* AF_INET only */

    in_port = in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {

        ngx_sort(in_port[p].addrs.elts, (size_t) in_port[p].addrs.nelts,
                 sizeof(ngx_http_conf_in_addr_t), ngx_http_cmp_conf_in_addrs);

        /*
         * check whether all name-based servers have the same configuraiton
         *     as the default server,
         * or some servers disable optimizing the server names
         */

        in_addr = in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {

            name = in_addr[a].names.elts;
            for (s = 0; s < in_addr[a].names.nelts; s++) {

                if (in_addr[a].core_srv_conf != name[s].core_srv_conf
                    || name[s].core_srv_conf->optimize_server_names == 0)
                {
                    goto virtual_names;
                }
            }

            /*
             * if all name-based servers have the same configuration
             *         as the default server,
             *     and no servers disable optimizing the server names
             * then we do not need to check them at run-time at all
             */

            in_addr[a].names.nelts = 0;

            continue;

        virtual_names:

            ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

            ha.temp_pool = ngx_create_pool(16384, cf->log);
            if (ha.temp_pool == NULL) {
                return NGX_CONF_ERROR;
            }

            ha.pool = cf->pool;

            if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
                ngx_destroy_pool(ha.temp_pool);
                return NGX_CONF_ERROR;
            }

#if (NGX_PCRE)
            regex = 0;
#endif

            name = in_addr[a].names.elts;

            for (s = 0; s < in_addr[a].names.nelts; s++) {

#if (NGX_PCRE)
                if (name[s].regex) {
                    regex++;
                    continue;
                }
#endif

                rc = ngx_hash_add_key(&ha, &name[s].name, name[s].core_srv_conf,
                                      NGX_HASH_WILDCARD_KEY);

                if (rc == NGX_ERROR) {
                    return NGX_CONF_ERROR;
                }

                if (rc == NGX_DECLINED) {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                "invalid server name or wildcard \"%V\" on %s",
                                &name[s].name, in_addr[a].listen_conf->addr);
                    return NGX_CONF_ERROR;
                }

                if (rc == NGX_BUSY) {
                    ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                                "conflicting server name \"%V\" on %s, ignored",
                                &name[s].name, in_addr[a].listen_conf->addr);
                }
            }

            hash.key = ngx_hash_key_lc;
            hash.max_size = cmcf->server_names_hash_max_size;
            hash.bucket_size = cmcf->server_names_hash_bucket_size;
            hash.name = "server_names_hash";
            hash.pool = cf->pool;

            if (ha.keys.nelts) {
                hash.hash = &in_addr[a].hash;
                hash.temp_pool = NULL;

                if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK)
                {
                    ngx_destroy_pool(ha.temp_pool);
                    return NGX_CONF_ERROR;
                }
            }

            if (ha.dns_wc_head.nelts) {

                ngx_qsort(ha.dns_wc_head.elts,
                          (size_t) ha.dns_wc_head.nelts,
                          sizeof(ngx_hash_key_t),
                          ngx_http_cmp_dns_wildcards);

                hash.hash = NULL;
                hash.temp_pool = ha.temp_pool;

                if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                           ha.dns_wc_head.nelts)
                    != NGX_OK)
                {
                    ngx_destroy_pool(ha.temp_pool);
                    return NGX_CONF_ERROR;
                }

                in_addr[a].wc_head = (ngx_hash_wildcard_t *) hash.hash;
            }

            if (ha.dns_wc_tail.nelts) {

                ngx_qsort(ha.dns_wc_tail.elts,
                          (size_t) ha.dns_wc_tail.nelts,
                          sizeof(ngx_hash_key_t),
                          ngx_http_cmp_dns_wildcards);

                hash.hash = NULL;
                hash.temp_pool = ha.temp_pool;

                if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                           ha.dns_wc_tail.nelts)
                    != NGX_OK)
                {
                    ngx_destroy_pool(ha.temp_pool);
                    return NGX_CONF_ERROR;
                }

                in_addr[a].wc_tail = (ngx_hash_wildcard_t *) hash.hash;
            }

            ngx_destroy_pool(ha.temp_pool);

#if (NGX_PCRE)

            if (regex == 0) {
                continue;
            }

            in_addr[a].nregex = regex;
            in_addr[a].regex = ngx_palloc(cf->pool,
                                       regex * sizeof(ngx_http_server_name_t));

            if (in_addr[a].regex == NULL) {
                return NGX_CONF_ERROR;
            }

            for (i = 0, s = 0; s < in_addr[a].names.nelts; s++) {
                if (name[s].regex) {
                    in_addr[a].regex[i++] = name[s];
                }
            }
#endif
        }

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

            ls->addr_ntop = 1;

            ls->handler = ngx_http_init_connection;

            cscf = in_addr[a].core_srv_conf;
            ls->pool_size = cscf->connection_pool_size;
            ls->post_accept_timeout = cscf->client_header_timeout;

            clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

            ls->log = *clcf->err_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

#if (NGX_WIN32)
            iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
            if (iocpcf->acceptex_read) {
                ls->post_accept_buffer_size = cscf->client_header_buffer_size;
            }
#endif

            ls->backlog = in_addr[a].listen_conf->backlog;
            ls->rcvbuf = in_addr[a].listen_conf->rcvbuf;
            ls->sndbuf = in_addr[a].listen_conf->sndbuf;

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            ls->accept_filter = in_addr[a].listen_conf->accept_filter;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            ls->deferred_accept = in_addr[a].listen_conf->deferred_accept;
#endif

            hip = ngx_palloc(cf->pool, sizeof(ngx_http_in_port_t));
            if (hip == NULL) {
                return NGX_CONF_ERROR;
            }

            hip->port = in_port[p].port;

            hip->port_text.data = ngx_palloc(cf->pool, 7);
            if (hip->port_text.data == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = hip;

            hip->port_text.len = ngx_sprintf(hip->port_text.data, ":%d",
                                             hip->port)
                                 - hip->port_text.data;

            in_addr = in_port[p].addrs.elts;

            if (in_addr[a].bind && in_addr[a].addr != INADDR_ANY) {
                hip->naddrs = 1;
                done = 0;

            } else if (in_port[p].addrs.nelts > 1
                       && in_addr[last - 1].addr == INADDR_ANY)
            {
                hip->naddrs = last;
                done = 1;

            } else {
                hip->naddrs = 1;
                done = 0;
            }

#if 0
            ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
                          "%ui: %V %d %ui %ui",
                          a, &ls->addr_text, in_addr[a].bind,
                          hip->naddrs, last);
#endif

            hip->addrs = ngx_pcalloc(cf->pool,
                                     hip->naddrs * sizeof(ngx_http_in_addr_t));
            if (hip->addrs == NULL) {
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < hip->naddrs; i++) {
                hip->addrs[i].addr = in_addr[i].addr;
                hip->addrs[i].core_srv_conf = in_addr[i].core_srv_conf;

                if (in_addr[i].hash.buckets == NULL
                    && (in_addr[i].wc_head == NULL
                        || in_addr[i].wc_head->hash.buckets == NULL)
                    && (in_addr[i].wc_head == NULL
                        || in_addr[i].wc_head->hash.buckets == NULL))
                {
                    continue;
                }

                vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
                if (vn == NULL) {
                    return NGX_CONF_ERROR;
                }
                hip->addrs[i].virtual_names = vn;

                vn->names.hash = in_addr[i].hash;
                vn->names.wc_head = in_addr[i].wc_head;
                vn->names.wc_tail = in_addr[i].wc_tail;
#if (NGX_PCRE)
                vn->nregex = in_addr[i].nregex;
                vn->regex = in_addr[i].regex;
#endif
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

#if 0
    {
    u_char      address[20];
    ngx_uint_t  p, a;

    in_port = in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                      "port: %d %p", in_port[p].port, &in_port[p]);
        in_addr = in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {
            ngx_inet_ntop(AF_INET, &in_addr[a].addr, address, 20);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                           "%s:%d %p",
                           address, in_port[p].port, in_addr[a].core_srv_conf);
            name = in_addr[a].names.elts;
            for (n = 0; n < in_addr[a].names.nelts; n++) {
                 ngx_log_debug4(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                                "%s:%d %V %p",
                                address, in_port[p].port, &name[n].name,
                                name[n].core_srv_conf);
            }
        }
    }
    }
#endif

    return NGX_CONF_OK;
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port (in_port)
 */

static ngx_int_t
ngx_http_add_address(ngx_conf_t *cf, ngx_http_conf_in_port_t *in_port,
    ngx_http_listen_t *lscf, ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_conf_in_addr_t  *in_addr;

    if (in_port->addrs.elts == NULL) {
        if (ngx_array_init(&in_port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_http_conf_in_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    in_addr = ngx_array_push(&in_port->addrs);
    if (in_addr == NULL) {
        return NGX_ERROR;
    }

    in_addr->addr = lscf->addr;
    in_addr->hash.buckets = NULL;
    in_addr->hash.size = 0;
    in_addr->wc_head = NULL;
    in_addr->wc_tail = NULL;
    in_addr->names.elts = NULL;
#if (NGX_PCRE)
    in_addr->nregex = 0;
    in_addr->regex = NULL;
#endif
    in_addr->core_srv_conf = cscf;
    in_addr->default_server = lscf->conf.default_server;
    in_addr->bind = lscf->conf.bind;
    in_addr->listen_conf = &lscf->conf;

#if (NGX_DEBUG)
    {
    u_char text[20];
    ngx_inet_ntop(AF_INET, &in_addr->addr, text, 20);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0, "address: %s:%d",
                   text, in_port->port);
    }
#endif

    return ngx_http_add_names(cf, in_addr, cscf);
}


/*
 * add the server names and the server core module
 * configurations to the address:port (in_addr)
 */

static ngx_int_t
ngx_http_add_names(ngx_conf_t *cf, ngx_http_conf_in_addr_t *in_addr,
    ngx_http_core_srv_conf_t *cscf)
{
    ngx_uint_t               i, n;
    ngx_http_server_name_t  *server_names, *name;

    if (in_addr->names.elts == NULL) {
        if (ngx_array_init(&in_addr->names, cf->temp_pool, 4,
                           sizeof(ngx_http_server_name_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    server_names = cscf->server_names.elts;

    for (i = 0; i < cscf->server_names.nelts; i++) {

        for (n = 0; n < server_names[i].name.len; n++) {
            server_names[i].name.data[n] =
                                     ngx_tolower(server_names[i].name.data[n]);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "name: %V", &server_names[i].name);

        name = ngx_array_push(&in_addr->names);
        if (name == NULL) {
            return NGX_ERROR;
        }

        *name = server_names[i];
    }

    return NGX_OK;
}


static char *
ngx_http_merge_locations(ngx_conf_t *cf, ngx_array_t *locations,
    void **loc_conf, ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                       *rv;
    ngx_uint_t                  i;
    ngx_http_core_loc_conf_t  **clcfp;

    clcfp = locations->elts;

    for (i = 0; i < locations->nelts; i++) {
        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcfp[i]->loc_conf[ctx_index]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        if (clcfp[i]->locations == NULL) {
            continue;
        }

        rv = ngx_http_merge_locations(cf, clcfp[i]->locations,
                                      clcfp[i]->loc_conf, module, ctx_index);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;
}


static int
ngx_http_cmp_conf_in_addrs(const void *one, const void *two)
{
    ngx_http_conf_in_addr_t  *first, *second;

    first = (ngx_http_conf_in_addr_t *) one;
    second = (ngx_http_conf_in_addr_t *) two;

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


static int ngx_libc_cdecl
ngx_http_cmp_dns_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_strcmp(first->key.data, second->key.data);
}
