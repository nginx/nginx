
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_config_file.h>
#include <ngx_http.h>
#include <ngx_http_core.h>
#include <ngx_http_config.h>
#include <ngx_http_write_filter.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_index_handler.h>


/* STUB */
void **ngx_srv_conf;
void **ngx_loc_conf;
/**/


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);
static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);


void **null_loc_conf;


static ngx_command_t  ngx_http_commands[] = {

    {ngx_string("http"),
     NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_http_block,
     0,
     0},

    {ngx_string(""), 0, NULL, 0, 0}
};


ngx_module_t  ngx_http_module = {
    NULL,                                  /* module context */
    ngx_http_commands,                     /* module directives */
    0,                                     /* module type */
    NULL                                   /* init module */
};

static ngx_command_t  ngx_http_core_commands[] = {

    {ngx_string("server"),
     NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_server_block,
     NGX_HTTP_MODULE_TYPE,
     0},

    {ngx_string(""), 0, NULL, 0, 0}
};


static ngx_http_module_t  ngx_http_core_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* init server config */
    NULL,                                  /* create location config */
    NULL,                                  /* merge location config */

    NULL,                                  /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    NULL,                                  /* output body filter */
    NULL                                   /* next output body filter */
};


ngx_module_t  ngx_http_core_module = {
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int  i;
    ngx_http_module_t    *module;
    ngx_http_conf_ctx_t  *ctx;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;
        module->index = ngx_http_max_module++;
    }

    ngx_test_null(null_loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    ctx->srv_conf = NULL;
    ctx->loc_conf = null_loc_conf;
    ctx->locations = NULL;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->create_loc_conf) {
            ngx_test_null(null_loc_conf[module->index],
                          module->create_loc_conf(cf->pool),
                          NGX_CONF_ERROR);
        }
    }

    cf->ctx = ctx;
    cf->type = NGX_HTTP_MODULE_TYPE;
    return ngx_conf_parse(cf, NULL);
}


static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int    i, j;
    char  *rv;
    void                ***loc_conf;     /* YES! 3 stars */
    ngx_http_module_t     *module;
    ngx_http_conf_ctx_t   *ctx, *prev;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    /* server config */
    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* server location config */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->create_srv_conf) {
            ngx_test_null(ctx->srv_conf[module->index],
                          module->create_srv_conf(cf->pool),
                          NGX_CONF_ERROR);
        }

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[module->index],
                          module->create_loc_conf(cf->pool),
                          NGX_CONF_ERROR);
        }
    }

    prev = cf->ctx;
    cf->ctx = ctx;
    rv = ngx_conf_parse(cf, NULL);
    cf->ctx = prev;

    if (rv != NULL)
        return rv;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->init_srv_conf) {
            if (module->init_srv_conf(cf->pool,
                                      ctx->srv_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->merge_loc_conf) {
            if (module->merge_loc_conf(cf->pool,
                                       prev->loc_conf[module->index],
                                       ctx->loc_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }

            loc_conf = (void ***)ctx->locations->elts;
            for (j = 0; j < ctx->locations->nelts; j++) {
                if (module->merge_loc_conf(cf->pool,
                                           ctx->loc_conf[module->index],
                                           loc_conf[j][module->index])
                                                           == NGX_CONF_ERROR) {
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    return NULL;
}


#if 0
int ngx_location_block(ngx_conf_t *cf)
{
    ngx_http_conf_ctx_t  *ctx, *prev;

    ngx_test_null(ctx, ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_ERROR);

    ctx->srv_conf = cf->ctx->srv_conf;

    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);

    for (i = 0; modules[i]; i++) {
        if (modules[i]->create_loc_conf)
            ngx_test_null(ctx->loc_conf[i],
                          modules[i]->create_loc_conf(cf->pool),
                          NGX_ERROR);

        if (ngx_http_core_module.index == i)
            ctx->loc_conf[i].location = cf->args[0];
    }

    push

    return ngx_conf_parse(cf);
}

#endif


int ngx_http_config_modules(ngx_pool_t *pool, ngx_module_t **modules)
{
    int i;
    ngx_http_module_t  *module;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) modules[i]->ctx;
        module->index = i;
    }

    ngx_http_max_module = i;

#if 0
    ngx_test_null(ngx_srv_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module),
                  NGX_ERROR);
    ngx_test_null(ngx_loc_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module),
                  NGX_ERROR);

    for (i = 0; modules[i]; i++) {
        if (modules[i]->create_srv_conf)
            ngx_srv_conf[i] = modules[i]->create_srv_conf(pool);

        if (modules[i]->create_loc_conf)
            ngx_loc_conf[i] = modules[i]->create_loc_conf(pool);
    }
#endif
}


void ngx_http_init_filters(ngx_pool_t *pool, ngx_module_t **modules)
{
    int  i;
    ngx_http_module_t  *module;
    int (*ohf)(ngx_http_request_t *r);
    int (*obf)(ngx_http_request_t *r, ngx_chain_t *ch);

    ohf = NULL;
    obf = NULL;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) modules[i]->ctx;
        if (module->output_header_filter) {
            module->next_output_header_filter = ohf;
            ohf = module->output_header_filter;
        }

        if (module->output_body_filter) {
            module->next_output_body_filter = obf;
            obf = module->output_body_filter;
        }
    }

    ngx_http_top_header_filter = ohf;
}
