
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


static char *ngx_imap_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_uint_t  ngx_imap_max_module;


static ngx_command_t  ngx_imap_commands[] = {

    { ngx_string("imap"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_imap_block,
      0,
      0,
      NULL },

      ngx_null_command
};

    
static ngx_core_module_t  ngx_imap_module_ctx = {
    ngx_string("imap"),
    NULL,
    NULL
};  


ngx_module_t  ngx_imap_module = {
    NGX_MODULE_V1,
    &ngx_imap_module_ctx,                  /* module context */
    ngx_imap_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static char *
ngx_imap_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   m, mi, s;
    ngx_conf_t                   pcf;
    ngx_imap_module_t           *module;
    ngx_imap_conf_ctx_t         *ctx;
    ngx_imap_core_srv_conf_t   **cscfp;
    ngx_imap_core_main_conf_t   *cmcf;

    /* the main imap context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_imap_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_imap_conf_ctx_t **) conf = ctx;

    /* count the number of the http modules and set up their indices */

    ngx_imap_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_IMAP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_imap_max_module++;
    }


    /* the imap main_conf context, it is the same in the all imap contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_imap_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the imap null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_imap_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all imap modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_IMAP_MODULE) {
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


    /* parse inside the imap{} block */

    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NGX_IMAP_MODULE;
    cf->cmd_type = NGX_IMAP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init imap{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_imap_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_IMAP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init imap{} main_conf's */

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
        }
    }

    /* imap{}'s cf->ctx was needed while the configuration merging */ 
    
    *cf = pcf; 

    return NGX_CONF_OK;
}
