
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_headers_in_hash(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_phase_handlers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

static ngx_int_t ngx_http_init_server_lists(ngx_conf_t *cf,
    ngx_array_t *servers, ngx_array_t *ports);
static ngx_int_t ngx_http_add_ports(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_array_t *ports,
    ngx_http_listen_t *listen);
static ngx_int_t ngx_http_add_addresses(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_t *listen);
static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_t *listen);
static ngx_int_t ngx_http_add_names(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_addr_t *addr);

static char *ngx_http_merge_locations(ngx_conf_t *cf,
    ngx_queue_t *locations, void **loc_conf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static ngx_int_t ngx_http_init_locations(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_cmp_locations(const ngx_queue_t *one,
    const ngx_queue_t *two);
static ngx_int_t ngx_http_join_exact_locations(ngx_conf_t *cf,
    ngx_queue_t *locations);
static void ngx_http_create_locations_list(ngx_queue_t *locations,
    ngx_queue_t *q);
static ngx_http_location_tree_node_t *
    ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix);

static ngx_int_t ngx_http_optimize_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_array_t *ports);
static ngx_int_t ngx_http_server_names(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_cmp_conf_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
    const void *two);

static ngx_int_t ngx_http_init_listening(ngx_conf_t *cf,
    ngx_http_conf_port_t *port);
static ngx_listening_t *ngx_http_add_listening(ngx_conf_t *cf,
    ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#endif

ngx_uint_t   ngx_http_max_module;


ngx_int_t  (*ngx_http_top_header_filter) (ngx_http_request_t *r);
ngx_int_t  (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


ngx_str_t  ngx_http_html_default_types[] = {
    ngx_string("text/html"),
    ngx_null_string
};


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
    ngx_uint_t                   mi, m, s;
    ngx_conf_t                   pcf;
    ngx_array_t                  ports;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

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
        goto failed;
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
                goto failed;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf, ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }

            if (module->merge_loc_conf) {

                /* merge the server{}'s loc_conf */

                rv = module->merge_loc_conf(cf, ctx->loc_conf[mi],
                                            cscfp[s]->ctx->loc_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }

                /* merge the locations{}' loc_conf's */

                clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

                rv = ngx_http_merge_locations(cf, clcf->locations,
                                              cscfp[s]->ctx->loc_conf,
                                              module, mi);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }
        }
    }


    /* create location trees */

    for (s = 0; s < cmcf->servers.nelts; s++) {

        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_http_init_locations(cf, cscfp[s], clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    if (ngx_http_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_init_headers_in_hash(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

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


    if (ngx_http_init_phase_handlers(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the lists of ports, addresses and server names
     * to find quickly the server core module configuration at run-time
     */

    if (ngx_http_init_server_lists(cf, &cmcf->servers, &ports) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    if (ngx_http_optimize_servers(cf, cmcf, &ports) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}


static ngx_int_t
ngx_http_init_phases(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_headers_in_hash(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_array_t         headers_in;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    ngx_http_header_t  *header;

    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (header = ngx_http_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
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
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_phase_handlers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_int_t                   j;
    ngx_uint_t                  i, n;
    ngx_uint_t                  find_config_index, use_rewrite, use_access;
    ngx_http_handler_pt        *h;
    ngx_http_phase_handler_t   *ph;
    ngx_http_phase_handler_pt   checker;

    cmcf->phase_engine.server_rewrite_index = (ngx_uint_t) -1;
    cmcf->phase_engine.location_rewrite_index = (ngx_uint_t) -1;
    find_config_index = 0;
    use_rewrite = cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    n = use_rewrite + use_access + cmcf->try_files + 1 /* find config phase */;

    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = ngx_pcalloc(cf->pool,
                     n * sizeof(ngx_http_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NGX_ERROR;
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

        case NGX_HTTP_TRY_FILES_PHASE:
            if (cmcf->try_files) {
                ph->checker = ngx_http_core_try_files_phase;
                n++;
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

    return NGX_OK;
}


static char *
ngx_http_merge_locations(ngx_conf_t *cf, ngx_queue_t *locations,
    void **loc_conf, ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                       *rv;
    ngx_queue_t                *q;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    if (locations == NULL) {
        return NGX_CONF_OK;
    }

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcf->loc_conf[ctx_index]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        rv = ngx_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
                                      module, ctx_index);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_init_locations(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_uint_t                   n;
    ngx_queue_t                 *q, *locations, *named, tail;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_location_queue_t   *lq;
    ngx_http_core_loc_conf_t   **clcfp;
#if (NGX_PCRE)
    ngx_uint_t                   r;
    ngx_queue_t                 *regex;
#endif

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    ngx_queue_sort(locations, ngx_http_cmp_locations);

    named = NULL;
    n = 0;
#if (NGX_PCRE)
    regex = NULL;
    r = 0;
#endif

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_locations(cf, NULL, clcf) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_PCRE)

        if (clcf->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }

#endif

        if (clcf->named) {
            n++;

            if (named == NULL) {
                named = q;
            }

            continue;
        }

        if (clcf->noname) {
            break;
        }
    }

    if (q != ngx_queue_sentinel(locations)) {
        ngx_queue_split(locations, q, &tail);
    }

    if (named) {
        clcfp = ngx_palloc(cf->pool,
                           (n + 1) * sizeof(ngx_http_core_loc_conf_t **));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        cscf->named_locations = clcfp;

        for (q = named;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, named, &tail);
    }

#if (NGX_PCRE)

    if (regex) {

        clcfp = ngx_palloc(cf->pool,
                           (r + 1) * sizeof(ngx_http_core_loc_conf_t **));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        pclcf->regex_locations = clcfp;

        for (q = regex;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, regex, &tail);
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_queue_t                *q, *locations;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    if (ngx_queue_empty(locations)) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_http_join_exact_locations(cf, locations) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_create_locations_list(locations, ngx_queue_head(locations));

    pclcf->static_locations = ngx_http_create_locations_tree(cf, locations, 0);
    if (pclcf->static_locations == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
    ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_location_queue_t  *lq;

    if (*locations == NULL) {
        *locations = ngx_palloc(cf->temp_pool,
                                sizeof(ngx_http_location_queue_t));
        if (*locations == NULL) {
            return NGX_ERROR;
        }

        ngx_queue_init(*locations);
    }

    lq = ngx_palloc(cf->temp_pool, sizeof(ngx_http_location_queue_t));
    if (lq == NULL) {
        return NGX_ERROR;
    }

    if (clcf->exact_match
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->named || clcf->noname)
    {
        lq->exact = clcf;
        lq->inclusive = NULL;

    } else {
        lq->exact = NULL;
        lq->inclusive = clcf;
    }

    lq->name = &clcf->name;
    lq->file_name = cf->conf_file->file.name.data;
    lq->line = cf->conf_file->line;

    ngx_queue_init(&lq->list);

    ngx_queue_insert_tail(*locations, &lq->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_http_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_int_t                   rc;
    ngx_http_core_loc_conf_t   *first, *second;
    ngx_http_location_queue_t  *lq1, *lq2;

    lq1 = (ngx_http_location_queue_t *) one;
    lq2 = (ngx_http_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return ngx_strcmp(first->name.data, second->name.data);
    }

#if (NGX_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = ngx_strcmp(first->name.data, second->name.data);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_join_exact_locations(ngx_conf_t *cf, ngx_queue_t *locations)
{
    ngx_queue_t                *q, *x;
    ngx_http_location_queue_t  *lq, *lx;

    q = ngx_queue_head(locations);

    while (q != ngx_queue_last(locations)) {

        x = ngx_queue_next(q);

        lq = (ngx_http_location_queue_t *) q;
        lx = (ngx_http_location_queue_t *) x;

        if (ngx_strcmp(lq->name->data, lx->name->data) == 0) {

            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "duplicate location \"%V\" in %s:%ui",
                              lx->name, lx->file_name, lx->line);

                return NGX_ERROR;
            }

            lq->inclusive = lx->inclusive;

            ngx_queue_remove(x);

            continue;
        }

        q = ngx_queue_next(q);
    }

    return NGX_OK;
}


static void
ngx_http_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    ngx_queue_t                *x, tail;
    ngx_http_location_queue_t  *lq, *lx;

    if (q == ngx_queue_last(locations)) {
        return;
    }

    lq = (ngx_http_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        ngx_http_create_locations_list(locations, ngx_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = ngx_queue_next(q);
         x != ngx_queue_sentinel(locations);
         x = ngx_queue_next(x))
    {
        lx = (ngx_http_location_queue_t *) x;

        if (len > lx->name->len
            || (ngx_strncmp(name, lx->name->data, len) != 0))
        {
            break;
        }
    }

    q = ngx_queue_next(q);

    if (q == x) {
        ngx_http_create_locations_list(locations, x);
        return;
    }

    ngx_queue_split(locations, q, &tail);
    ngx_queue_add(&lq->list, &tail);

    if (x == ngx_queue_sentinel(locations)) {
        ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
        return;
    }

    ngx_queue_split(&lq->list, x, &tail);
    ngx_queue_add(locations, &tail);

    ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));

    ngx_http_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

static ngx_http_location_tree_node_t *
ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix)
{
    size_t                          len;
    ngx_queue_t                    *q, tail;
    ngx_http_location_queue_t      *lq;
    ngx_http_location_tree_node_t  *node;

    q = ngx_queue_middle(locations);

    lq = (ngx_http_location_queue_t *) q;
    len = lq->name->len - prefix;

    node = ngx_palloc(cf->pool,
                      offsetof(ngx_http_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
                           || (lq->inclusive && lq->inclusive->auto_redirect));

    node->len = (u_char) len;
    ngx_memcpy(node->name, &lq->name->data[prefix], len);

    ngx_queue_split(locations, q, &tail);

    if (ngx_queue_empty(locations)) {
        /*
         * ngx_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = ngx_http_create_locations_tree(cf, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    ngx_queue_remove(q);

    if (ngx_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = ngx_http_create_locations_tree(cf, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

inclusive:

    if (ngx_queue_empty(&lq->list)) {
        return node;
    }

    node->tree = ngx_http_create_locations_tree(cf, &lq->list, prefix + len);
    if (node->tree == NULL) {
        return NULL;
    }

    return node;
}


static ngx_int_t
ngx_http_init_server_lists(ngx_conf_t *cf, ngx_array_t *servers,
    ngx_array_t *ports)
{
    ngx_uint_t                  s, i;
    ngx_http_listen_t          *listen;
    ngx_http_core_srv_conf_t  **cscfp;

    if (ngx_array_init(ports, cf->temp_pool, 2, sizeof(ngx_http_conf_port_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* "server" directives */

    cscfp = servers->elts;
    for (s = 0; s < servers->nelts; s++) {

        /* "listen" directives */

        listen = cscfp[s]->listen.elts;
        for (i = 0; i < cscfp[s]->listen.nelts; i++) {

            if (ngx_http_add_ports(cf, cscfp[s], ports, &listen[i]) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_add_ports(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_array_t *ports, ngx_http_listen_t *listen)
{
    in_port_t                 p;
    ngx_uint_t                i;
    struct sockaddr          *sa;
    struct sockaddr_in       *sin;
    ngx_http_conf_port_t     *port;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6      *sin6;
#endif

    sa = (struct sockaddr *) &listen->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        p = sin6->sin6_port;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        p = sin->sin_port;
        break;
    }

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {

        if (p != port[i].port || sa->sa_family != port[i].family) {
            continue;
        }

        /* a port is already in the port list */

        return ngx_http_add_addresses(cf, cscf, &port[i], listen);
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;
    port->addrs.elts = NULL;

    return ngx_http_add_address(cf, cscf, port, listen);
}


static ngx_int_t
ngx_http_add_addresses(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_t *listen)
{
    u_char                *p;
    size_t                 len, off;
    ngx_uint_t             i;
    struct sockaddr       *sa;
    ngx_http_conf_addr_t  *addr;

    /*
     * we can not compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    sa = (struct sockaddr *) &listen->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        off = offsetof(struct sockaddr_in6, sin6_addr);
        len = 16;
        break;
#endif

    default: /* AF_INET */
        off = offsetof(struct sockaddr_in, sin_addr);
        len = 4;
        break;
    }

    p = listen->sockaddr + off;

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (ngx_memcmp(p, (u_char *) addr[i].sockaddr + off, len) != 0) {
            continue;
        }

        /* the address is already in the address list */

        if (ngx_http_add_names(cf, cscf, &addr[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        /* check the duplicate "default" server for this address:port */

        if (listen->conf.default_server) {

            if (addr[i].default_server) {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                              "the duplicate default server in %s:%ui",
                               listen->file_name, listen->line);

                return NGX_ERROR;
            }

            addr[i].core_srv_conf = cscf;
            addr[i].default_server = 1;
#if (NGX_HTTP_SSL)
            addr[i].ssl = listen->conf.ssl;
#endif
            addr[i].listen_conf = &listen->conf;
        }

        return NGX_OK;
    }

    /* add the address to the addresses list that bound to this port */

    return ngx_http_add_address(cf, cscf, port, listen);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

static ngx_int_t
ngx_http_add_address(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_t *listen)
{
    ngx_http_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_http_conf_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
    addr->socklen = listen->socklen;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
    addr->names.elts = NULL;
#if (NGX_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    addr->core_srv_conf = cscf;
    addr->default_server = listen->conf.default_server;
    addr->bind = listen->conf.bind;
    addr->wildcard = listen->conf.wildcard;
#if (NGX_HTTP_SSL)
    addr->ssl = listen->conf.ssl;
#endif
    addr->listen_conf = &listen->conf;

    return ngx_http_add_names(cf, cscf, addr);
}


/*
 * add the server names and the server core module
 * configurations to the address:port
 */

static ngx_int_t
ngx_http_add_names(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t               i;
    ngx_http_server_name_t  *server_names, *name;

    if (addr->names.elts == NULL) {
        if (ngx_array_init(&addr->names, cf->temp_pool, 4,
                           sizeof(ngx_http_server_name_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    server_names = cscf->server_names.elts;

    for (i = 0; i < cscf->server_names.nelts; i++) {

        ngx_strlow(server_names[i].name.data, server_names[i].name.data,
                   server_names[i].name.len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "name: %V", &server_names[i].name);

        name = ngx_array_push(&addr->names);
        if (name == NULL) {
            return NGX_ERROR;
        }

        *name = server_names[i];
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_array_t *ports)
{
    ngx_uint_t               s, p, a;
    ngx_http_conf_port_t    *port;
    ngx_http_conf_addr_t    *addr;
    ngx_http_server_name_t  *name;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_http_conf_addr_t), ngx_http_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuraiton as a default server for given address:port
         */

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            name = addr[a].names.elts;
            for (s = 0; s < addr[a].names.nelts; s++) {

                if (addr[a].core_srv_conf == name[s].core_srv_conf
#if (NGX_PCRE)
                    && name[s].captures == 0
#endif
                    )
                {
                    continue;
                }

                if (ngx_http_server_names(cf, cmcf, &addr[a]) != NGX_OK) {
                    return NGX_ERROR;
                }

                break;
            }
        }

        if (ngx_http_init_listening(cf, &port[p]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_conf_addr_t *addr)
{
    ngx_int_t                rc;
    ngx_uint_t               s;
    ngx_hash_init_t          hash;
    ngx_hash_keys_arrays_t   ha;
    ngx_http_server_name_t  *name;
#if (NGX_PCRE)
    ngx_uint_t               regex, i;

    regex = 0;
#endif

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(16384, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    name = addr->names.elts;

    for (s = 0; s < addr->names.nelts; s++) {

#if (NGX_PCRE)
        if (name[s].regex) {
            regex++;
            continue;
        }
#endif

        rc = ngx_hash_add_key(&ha, &name[s].name, name[s].core_srv_conf,
                              NGX_HASH_WILDCARD_KEY);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "invalid server name or wildcard \"%V\" on %s",
                          &name[s].name, addr->listen_conf->addr);
            return NGX_ERROR;
        }

        if (rc == NGX_BUSY) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "conflicting server name \"%V\" on %s, ignored",
                          &name[s].name, addr->listen_conf->addr);
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

#if (NGX_PCRE)

    if (regex == 0) {
        return NGX_OK;
    }

    addr->nregex = regex;
    addr->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_server_name_t));
    if (addr->regex == NULL) {
        return NGX_ERROR;
    }

    for (i = 0, s = 0; s < addr->names.nelts; s++) {
        if (name[s].regex) {
            addr->regex[i++] = name[s];
        }
    }

#endif

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_http_conf_addr_t  *first, *second;

    first = (ngx_http_conf_addr_t *) one;
    second = (ngx_http_conf_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
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

    return ngx_dns_strcmp(first->key.data, second->key.data);
}


static ngx_int_t
ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_port_t *port)
{
    ngx_uint_t                 i, last, bind_wildcard;
    ngx_listening_t           *ls;
    ngx_http_port_t           *hport;
    ngx_http_conf_addr_t      *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    if (addr[last - 1].wildcard) {
        addr[last - 1].bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    while (i < last) {

        if (bind_wildcard && !addr[i].bind) {
            i++;
            continue;
        }

        ls = ngx_http_add_listening(cf, &addr[i]);
        if (ls == NULL) {
            return NGX_ERROR;
        }

        hport = ngx_pcalloc(cf->pool, sizeof(ngx_http_port_t));
        if (hport == NULL) {
            return NGX_ERROR;
        }

        ls->servers = hport;

        if (i == last - 1) {
            hport->naddrs = last;

        } else {
            hport->naddrs = 1;
            i = 0;
        }

        switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            if (ngx_http_add_addrs6(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (ngx_http_add_addrs(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        }

        addr++;
        last--;
    }

    return NGX_OK;
}


static ngx_listening_t *
ngx_http_add_listening(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
{
    ngx_listening_t           *ls;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    ls = ngx_create_listening(cf, addr->sockaddr, addr->socklen);
    if (ls == NULL) {
        return NULL;
    }

    ls->addr_ntop = 1;

    ls->handler = ngx_http_init_connection;

    cscf = addr->core_srv_conf;
    ls->pool_size = cscf->connection_pool_size;
    ls->post_accept_timeout = cscf->client_header_timeout;

    clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    ls->logp = clcf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

#if (NGX_WIN32)
    {
    ngx_iocp_conf_t  *iocpcf;

    iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
    if (iocpcf->acceptex_read) {
        ls->post_accept_buffer_size = cscf->client_header_buffer_size;
    }
    }
#endif

    ls->backlog = addr->listen_conf->backlog;
    ls->rcvbuf = addr->listen_conf->rcvbuf;
    ls->sndbuf = addr->listen_conf->sndbuf;

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->listen_conf->accept_filter;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->listen_conf->deferred_accept;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = addr->listen_conf->ipv6only;
#endif

    return ls;
}


static ngx_int_t
ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in_addr_t        *addrs;
    struct sockaddr_in        *sin;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.core_srv_conf = addr[i].core_srv_conf;
#if (NGX_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].ssl;
#endif

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in6_addr_t       *addrs6;
    struct sockaddr_in6       *sin6;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in6_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.core_srv_conf = addr[i].core_srv_conf;
#if (NGX_HTTP_SSL)
        addrs6[i].conf.ssl = addr[i].ssl;
#endif

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL))
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}

#endif


char *
ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_array_t     **types;
    ngx_str_t        *value, *default_type;
    ngx_uint_t        i, n, hash;
    ngx_hash_key_t   *type;

    types = (ngx_array_t **) (p + cmd->offset);

    default_type = cmd->post;

    if (*types == NULL) {
        *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
        if (*types == NULL) {
            return NGX_CONF_ERROR;
        }

        if (default_type) {
            type = ngx_array_push(*types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->key = *default_type;
            type->key_hash = ngx_hash_key(default_type->data,
                                          default_type->len);
            type->value = (void *) 4;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);
        value[i].data[value[i].len] = '\0';

        type = (*types)->elts;
        for (n = 0; n < (*types)->nelts; n++) {

            if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate MIME type \"%V\"", &value[i]);
                continue;
            }
        }

        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = (void *) 4;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t *keys, ngx_hash_t *types_hash,
    ngx_array_t *prev_keys, ngx_hash_t *prev_types_hash,
    ngx_str_t *default_types)
{
    ngx_hash_init_t  hash;

    if (keys) {

        hash.hash = types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, keys->elts, keys->nelts) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (prev_types_hash->buckets == NULL) {

        if (prev_keys == NULL) {

            if (ngx_http_set_default_types(cf, &prev_keys, default_types)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        hash.hash = prev_types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, prev_keys->elts, prev_keys->nelts) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    *types_hash = *prev_types_hash;

    return NGX_CONF_OK;

}


ngx_int_t
ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
    ngx_str_t *default_type)
{
    ngx_hash_key_t  *type;

    *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
    if (*types == NULL) {
        return NGX_ERROR;
    }

    while (default_type->len) {

        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_ERROR;
        }

        type->key = *default_type;
        type->key_hash = ngx_hash_key(default_type->data,
                                      default_type->len);
        type->value = (void *) 4;

        default_type++;
    }

    return NGX_OK;
}
