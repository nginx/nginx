
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_config_file.h>
#include <ngx_http.h>
#include <ngx_http_write_filter.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_index_handler.h>


int ngx_max_module;

int (*ngx_http_top_header_filter) (ngx_http_request_t *r);

/* STUB: gobal srv and loc conf */
void **ngx_srv_conf;
void **ngx_loc_conf;

#if 0
int ngx_http_block(ngx_conf_t *cf)
{
    ngx_http_conf_ctx_t  *ctx;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_ERROR);

#if 0
    /* null server config */
    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);
#endif

    /* null location config */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);

    for (i = 0; modules[i]; i++) {
#if 0
        if (modules[i]->create_srv_conf)
            ngx_test_null(ctx->srv_conf[i],
                          modules[i]->create_srv_conf(cf->pool),
                          NGX_ERROR);
#endif

        if (modules[i]->create_loc_conf)
            ngx_test_null(ctx->loc_conf[i],
                          modules[i]->create_loc_conf(cf->pool),
                          NGX_ERROR);
    }

    cf->ctx = ctx;
    return ngx_conf_parse(cf);
}

int ngx_server_block(ngx_conf_t *cf)
{
    ngx_http_conf_ctx_t  *ctx, *prev;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_ERROR);

    /* server config */
    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);

    /* server location config */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);


    for (i = 0; modules[i]; i++) {
        if (modules[i]->create_srv_conf)
            ngx_test_null(ctx->srv_conf[i],
                          modules[i]->create_srv_conf(cf->pool),
                          NGX_ERROR);

        if (modules[i]->create_loc_conf)
            ngx_test_null(ctx->loc_conf[i],
                          modules[i]->create_loc_conf(cf->pool),
                          NGX_ERROR);
    }

    prev = cf->ctx;
    cf->ctx = ctx;
    rc = ngx_conf_parse(cf);
    cf->ctx = prev;

    if (loc == NGX_ERROR)
        return NGX_ERROR;

    for (i = 0; modules[i]; i++) {
#if 0
        if (modules[i]->merge_srv_conf)
            if (modules[i]->merge_srv_conf(cf->pool,
                                           prev->srv_conf, ctx->srv_conf)
                                                                  == NGX_ERROR)
                return NGX_ERROR;
#endif

        if (modules[i]->init_srv_conf)
            if (modules[i]->init_srv_conf(cf->pool, ctx->srv_conf) == NGX_ERROR)
                return NGX_ERROR;

        if (modules[i]->merge_loc_conf)
            if (modules[i]->merge_loc_conf(cf->pool,
                                           prev->loc_conf, ctx->loc_conf)
                                                                  == NGX_ERROR)
                return NGX_ERROR;

            for (array) {
                if (modules[i]->merge_loc_conf(cf->pool,
                                               ctx->loc_conf, loc->loc_conf)
                                                                  == NGX_ERROR)
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

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

int ngx_http_config_modules(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;

    for (i = 0; modules[i]; i++) {
        modules[i]->index = i;
    }

    ngx_max_module = i;

    ngx_test_null(ngx_srv_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);
    ngx_test_null(ngx_loc_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);

    for (i = 0; modules[i]; i++) {
        if (modules[i]->create_srv_conf)
            ngx_srv_conf[i] = modules[i]->create_srv_conf(pool);

        if (modules[i]->create_loc_conf)
            ngx_loc_conf[i] = modules[i]->create_loc_conf(pool);
    }
}

int ngx_http_init_modules(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->init_module)
            modules[i]->init_module(pool);
    }
}

int ngx_http_init_filters(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    int (*ohf)(ngx_http_request_t *r);
    int (*obf)(ngx_http_request_t *r, ngx_chain_t *ch);

    ohf = NULL;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->output_header_filter) {
            modules[i]->next_output_header_filter = ohf;
            ohf = modules[i]->output_header_filter;
        }
    }

    ngx_http_top_header_filter = ohf;

    obf = NULL;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->output_body_filter) {
            modules[i]->next_output_body_filter = obf;
            obf = modules[i]->output_body_filter;
        }
    }
}


/* STUB */
ngx_http_output_filter_set_stub(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    ngx_command_t *cmd;

    for (i = 0; modules[i]; i++) {
        if (modules[i] == &ngx_http_output_filter_module) {
            for (cmd = modules[i]->commands; cmd->name; cmd++) {
                if (strcmp(cmd->name, "output_buffer") == 0) {
                    cmd->set(ngx_loc_conf[i], cmd->offset, "32768");
                }
            }
        }
    }
}

ngx_http_write_filter_set_stub(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    ngx_command_t *cmd;

    for (i = 0; modules[i]; i++) {
        if (modules[i] == &ngx_http_write_filter_module) {
            for (cmd = modules[i]->commands; cmd->name; cmd++) {
                if (strcmp(cmd->name, "write_buffer") == 0) {
                    cmd->set(ngx_loc_conf[i], cmd->offset, "1500");
                }
            }
        }
    }
}

ngx_http_index_set_stub(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    ngx_str_t index;
    ngx_command_t *cmd;

    for (i = 0; modules[i]; i++) {
        if (modules[i] == &ngx_http_index_module) {
            for (cmd = modules[i]->commands; cmd->name; cmd++) {
                if (strcmp(cmd->name, "index") == 0) {
                    index.len = sizeof("index.html") - 1;
                    index.data = "index.html";
                    cmd->set(pool, ngx_loc_conf[i], &index);
                }
            }
        }
    }
}
