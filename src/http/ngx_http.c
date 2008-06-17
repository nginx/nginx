
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_headers_in_hash(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_phase_handlers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

static ngx_int_t ngx_http_init_server_lists(ngx_conf_t *cf,
    ngx_array_t *servers, ngx_array_t *in_ports);
static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_in_port_t *in_port,
    ngx_http_listen_t *listen);
static ngx_int_t ngx_http_add_names(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_in_addr_t *in_addr);

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
    ngx_http_core_main_conf_t *cmcf, ngx_array_t *in_ports);
static ngx_int_t ngx_http_cmp_conf_in_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
    const void *two);

static ngx_int_t ngx_http_init_listening(ngx_conf_t *cf,
    ngx_http_conf_in_port_t *in_port);

ngx_uint_t   ngx_http_max_module;


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
    ngx_uint_t                   mi, m, s;
    ngx_conf_t                   pcf;
    ngx_array_t                  in_ports;
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

    /* AF_INET only */

    if (ngx_http_init_server_lists(cf, &cmcf->servers, &in_ports) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    /* AF_INET only */

    if (ngx_http_optimize_servers(cf, cmcf, &in_ports) != NGX_OK) {
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

    n = use_rewrite + use_access + 1; /* find config phase */

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
    ngx_array_t *in_ports)
{
    ngx_uint_t                  s, l, p, a;
    ngx_http_listen_t          *listen;
    ngx_http_conf_in_port_t    *in_port;
    ngx_http_conf_in_addr_t    *in_addr;
    ngx_http_core_srv_conf_t  **cscfp;

    if (ngx_array_init(in_ports, cf->temp_pool, 2,
                       sizeof(ngx_http_conf_in_port_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* "server" directives */

    cscfp = servers->elts;
    for (s = 0; s < servers->nelts; s++) {

        /* "listen" directives */

        listen = cscfp[s]->listen.elts;
        for (l = 0; l < cscfp[s]->listen.nelts; l++) {

            /* AF_INET only */

            in_port = in_ports->elts;
            for (p = 0; p < in_ports->nelts; p++) {

                if (listen[l].port != in_port[p].port) {
                    continue;
                }

                /* the port is already in the port list */

                in_addr = in_port[p].addrs.elts;
                for (a = 0; a < in_port[p].addrs.nelts; a++) {

                    if (listen[l].addr != in_addr[a].addr) {
                        continue;
                    }

                    /* the address is already in the address list */

                    if (ngx_http_add_names(cf, cscfp[s], &in_addr[a]) != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    /*
                     * check the duplicate "default" server
                     * for this address:port
                     */

                    if (listen[l].conf.default_server) {

                        if (in_addr[a].default_server) {
                            ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                                      "the duplicate default server in %s:%ui",
                                       listen[l].file_name, listen[l].line);

                            return NGX_ERROR;
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

                if (ngx_http_add_address(cf, cscfp[s], &in_port[p], &listen[l])
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                goto found;
            }

            /* add the port to the in_port list */

            in_port = ngx_array_push(in_ports);
            if (in_port == NULL) {
                return NGX_ERROR;
            }

            in_port->port = listen[l].port;
            in_port->addrs.elts = NULL;

            if (ngx_http_add_address(cf, cscfp[s], in_port, &listen[l])
                != NGX_OK)
            {
                return NGX_ERROR;
            }

        found:

            continue;
        }
    }

    return NGX_OK;
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port (in_port)
 */

static ngx_int_t
ngx_http_add_address(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
     ngx_http_conf_in_port_t *in_port, ngx_http_listen_t *listen)
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

    in_addr->addr = listen->addr;
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
    in_addr->default_server = listen->conf.default_server;
    in_addr->bind = listen->conf.bind;
    in_addr->listen_conf = &listen->conf;

#if (NGX_DEBUG)
    {
    u_char text[20];
    ngx_inet_ntop(AF_INET, &in_addr->addr, text, 20);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0, "address: %s:%d",
                   text, in_port->port);
    }
#endif

    return ngx_http_add_names(cf, cscf, in_addr);
}


/*
 * add the server names and the server core module
 * configurations to the address:port (in_addr)
 */

static ngx_int_t
ngx_http_add_names(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_in_addr_t *in_addr)
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


static ngx_int_t
ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_array_t *in_ports)
{
    ngx_int_t                  rc;
    ngx_uint_t                 s, p, a;
    ngx_hash_init_t            hash;
    ngx_http_server_name_t    *name;
    ngx_hash_keys_arrays_t     ha;
    ngx_http_conf_in_port_t   *in_port;
    ngx_http_conf_in_addr_t   *in_addr;
#if (NGX_PCRE)
    ngx_uint_t                 regex, i;
#endif

    in_port = in_ports->elts;
    for (p = 0; p < in_ports->nelts; p++) {

        ngx_sort(in_port[p].addrs.elts, (size_t) in_port[p].addrs.nelts,
                 sizeof(ngx_http_conf_in_addr_t), ngx_http_cmp_conf_in_addrs);

        /*
         * check whether all name-based servers have
         * the same configuraiton as the default server
         */

        in_addr = in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {

            name = in_addr[a].names.elts;
            for (s = 0; s < in_addr[a].names.nelts; s++) {

                if (in_addr[a].core_srv_conf != name[s].core_srv_conf) {
                    goto virtual_names;
                }
            }

            /*
             * if all name-based servers have the same configuration
             * as the default server, then we do not need to check
             * them at run-time at all
             */

            in_addr[a].names.nelts = 0;

            continue;

        virtual_names:

            ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

            ha.temp_pool = ngx_create_pool(16384, cf->log);
            if (ha.temp_pool == NULL) {
                return NGX_ERROR;
            }

            ha.pool = cf->pool;

            if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
                goto failed;
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
                    return NGX_ERROR;
                }

                if (rc == NGX_DECLINED) {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                "invalid server name or wildcard \"%V\" on %s",
                                &name[s].name, in_addr[a].listen_conf->addr);
                    return NGX_ERROR;
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
                    goto failed;
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
                    goto failed;
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
                    goto failed;
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
                return NGX_ERROR;
            }

            for (i = 0, s = 0; s < in_addr[a].names.nelts; s++) {
                if (name[s].regex) {
                    in_addr[a].regex[i++] = name[s];
                }
            }
#endif
        }

        if (ngx_http_init_listening(cf, &in_port[p]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
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


static ngx_int_t
ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_in_port_t *in_port)
{
    ngx_uint_t                 i, a, last, bind_all, done;
    ngx_listening_t           *ls;
    ngx_http_in_port_t        *hip;
    ngx_http_conf_in_addr_t   *in_addr;
    ngx_http_virtual_names_t  *vn;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    in_addr = in_port->addrs.elts;
    last = in_port->addrs.nelts;

    /*
     * if there is a binding to a "*:port" then we need to bind()
     * to the "*:port" only and ignore other bindings
     */

    if (in_addr[last - 1].addr == INADDR_ANY) {
        in_addr[last - 1].bind = 1;
        bind_all = 0;

    } else {
        bind_all = 1;
    }

    a = 0;

    while (a < last) {

        if (!bind_all && !in_addr[a].bind) {
            a++;
            continue;
        }

        ls = ngx_listening_inet_stream_socket(cf, in_addr[a].addr,
                                              in_port->port);
        if (ls == NULL) {
            return NGX_ERROR;
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
        {
        ngx_iocp_conf_t  *iocpcf;

        iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
        if (iocpcf->acceptex_read) {
            ls->post_accept_buffer_size = cscf->client_header_buffer_size;
        }
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
            return NGX_ERROR;
        }

        hip->port = in_port->port;

        hip->port_text.data = ngx_pnalloc(cf->pool, 7);
        if (hip->port_text.data == NULL) {
            return NGX_ERROR;
        }

        ls->servers = hip;

        hip->port_text.len = ngx_sprintf(hip->port_text.data, ":%d", hip->port)
                             - hip->port_text.data;

        in_addr = in_port->addrs.elts;

        if (in_addr[a].bind && in_addr[a].addr != INADDR_ANY) {
            hip->naddrs = 1;
            done = 0;

        } else if (in_port->addrs.nelts > 1
                   && in_addr[last - 1].addr == INADDR_ANY)
        {
            hip->naddrs = last;
            done = 1;

        } else {
            hip->naddrs = 1;
            done = 0;
        }

        hip->addrs = ngx_pcalloc(cf->pool,
                                 hip->naddrs * sizeof(ngx_http_in_addr_t));
        if (hip->addrs == NULL) {
            return NGX_ERROR;
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
                return NGX_ERROR;
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
            return NGX_OK;
        }

        in_addr++;
        in_port->addrs.elts = in_addr;
        last--;

        a = 0;
    }

    return NGX_OK;
}
