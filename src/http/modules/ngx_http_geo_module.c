
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_radix_tree_t  *tree;
    ngx_pool_t        *pool;
    ngx_array_t        values;
} ngx_http_geo_conf_ctx_t;


static char *ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);


static ngx_command_t  ngx_http_geo_commands[] = {

    { ngx_string("geo"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_geo_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_geo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_geo_module = {
    NGX_MODULE_V1,
    &ngx_http_geo_module_ctx,              /* module context */
    ngx_http_geo_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* AF_INET only */

static ngx_int_t
ngx_http_geo_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_radix_tree_t *tree = (ngx_radix_tree_t *) data;

    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *vv;

    sin = (struct sockaddr_in *) r->connection->sockaddr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo started");

    vv = (ngx_http_variable_value_t *)
                       ngx_radix32tree_find(tree, ntohl(sin->sin_addr.s_addr));

    *v = *vv;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo: %V %v", &r->connection->addr_text, v);

    return NGX_OK;
}


static char *
ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    ngx_str_t                *value, name;
    ngx_conf_t                save;
    ngx_pool_t               *pool;
    ngx_radix_tree_t         *tree;
    ngx_http_variable_t      *var;
    ngx_http_geo_conf_ctx_t   ctx;

    value = cf->args->elts;

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"%V\" variable name should start with '$'",
                           &value[1]);
    } else {
        name.len--;
        name.data++;
    }

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    tree = ngx_radix_tree_create(cf->pool, -1);

    if (tree == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_geo_variable;
    var->data = (uintptr_t) tree;

    pool = ngx_create_pool(16384, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&ctx.values, pool, 512,
                       sizeof(ngx_http_variable_value_t *))
        != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_CONF_ERROR;
    }

    ctx.tree = tree;
    ctx.pool = cf->pool;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = ngx_http_geo;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    ngx_destroy_pool(pool);

    if (ngx_radix32tree_find(tree, 0) != NGX_RADIX_NO_VALUE) {
        return rv;
    }

    if (ngx_radix32tree_insert(tree, 0, 0,
                               (uintptr_t) &ngx_http_variable_null_value)
        == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return rv;
}


/* AF_INET only */

static char *
ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_int_t                   rc;
    ngx_str_t                  *value, file;
    ngx_uint_t                  i;
    ngx_inet_cidr_t             cidrin;
    ngx_http_geo_conf_ctx_t    *ctx;
    ngx_http_variable_value_t  *var, *old, **v;

    ctx = cf->ctx;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of the geo parameters");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        file = value[1];

        if (ngx_conf_full_name(cf->cycle, &file) == NGX_ERROR){
            return NGX_CONF_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return ngx_conf_parse(cf, &file);
    }

    if (ngx_strcmp(value[0].data, "default") == 0) {
        cidrin.addr = 0;
        cidrin.mask = 0;

    } else {
        rc = ngx_ptocidr(&value[0], &cidrin);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[0]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[0]);
        }

        cidrin.addr = ntohl(cidrin.addr);
        cidrin.mask = ntohl(cidrin.mask);
    }

    var = NULL;
    v = ctx->values.elts;

    for (i = 0; i < ctx->values.nelts; i++) {
        if ((size_t) v[i]->len != value[1].len) {
            continue;
        }

        if (ngx_strncmp(value[1].data, v[i]->data, value[1].len) == 0) {
            var = v[i];
            break;
        }
    }

    if (var == NULL) {
        var = ngx_palloc(ctx->pool, sizeof(ngx_http_variable_value_t));
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        var->len = value[1].len;
        var->data = ngx_pstrdup(ctx->pool, &value[1]);
        if (var->data == NULL) {
            return NGX_CONF_ERROR;
        }

        var->valid = 1;
        var->no_cacheable = 0;
        var->not_found = 0;

        v = ngx_array_push(&ctx->values);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }

        *v = var;
    }

    for (i = 2; i; i--) {
        rc = ngx_radix32tree_insert(ctx->tree, cidrin.addr, cidrin.mask,
                                    (uintptr_t) var);
        if (rc == NGX_OK) {
            return NGX_CONF_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        /* rc == NGX_BUSY */

        old  = (ngx_http_variable_value_t *)
                    ngx_radix32tree_find(ctx->tree, cidrin.addr & cidrin.mask);

        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "duplicate parameter \"%V\", value: \"%v\", old value: \"%v\"",
                &value[0], var, old);

        rc = ngx_radix32tree_delete(ctx->tree, cidrin.addr, cidrin.mask);

        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_ERROR;
}
