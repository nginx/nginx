
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
} ngx_http_geo_conf_t;


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


static ngx_http_variable_value_t  ngx_http_geo_null_value =
                                                        { 0, ngx_string("0") };


/* AF_INET only */

static ngx_http_variable_value_t *
ngx_http_geo_variable(ngx_http_request_t *r, uintptr_t data)
{
    ngx_radix_tree_t *tree = (ngx_radix_tree_t *) data;

    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *var;

    sin = (struct sockaddr_in *) r->connection->sockaddr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo started");

    var  = (ngx_http_variable_value_t *)
                       ngx_radix32tree_find(tree, ntohl(sin->sin_addr.s_addr));

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo: %V %V", &r->connection->addr_text, &var->text);

    return var;
}


static char *
ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                 *rv;
    ngx_str_t            *value, name;
    ngx_conf_t            save;
    ngx_pool_t           *pool;
    ngx_radix_tree_t     *tree;
    ngx_http_geo_conf_t   geo;
    ngx_http_variable_t  *var;

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

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    tree = ngx_radix_tree_create(cf->pool, -1);
    if (tree == NULL) {
        return NGX_CONF_ERROR;
    }

    var->handler = ngx_http_geo_variable;
    var->data = (uintptr_t) tree;

    /*
     * create the temporary pool of a huge initial size
     * to process quickly a large number of geo lines
     */

    pool = ngx_create_pool(512 * 1024, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&geo.values, pool, 512,
                       sizeof(ngx_http_variable_value_t *)) == NGX_ERROR)
    {
        ngx_destroy_pool(pool);
        return NGX_CONF_ERROR;
    }

    geo.tree = tree;
    geo.pool = cf->pool;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &geo;
    cf->handler = ngx_http_geo;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    ngx_destroy_pool(pool);

    if (ngx_radix32tree_find(tree, 0) != NGX_RADIX_NO_VALUE) {
        return rv;
    }

    if (ngx_radix32tree_insert(tree, 0, 0,
                            (uintptr_t) &ngx_http_geo_null_value) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return rv;
}


/* AF_INET only */

static char *
ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_int_t                   rc, n;
    ngx_str_t                  *value, file;
    ngx_uint_t                  i;
    ngx_inet_cidr_t             cidrin;
    ngx_http_geo_conf_t        *geo;
    ngx_http_variable_value_t  *var, *old, **v;

    geo = cf->ctx;

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
        if (ngx_ptocidr(&value[0], &cidrin) == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[0]);
            return NGX_CONF_ERROR;
        }

        cidrin.addr = ntohl(cidrin.addr);
        cidrin.mask = ntohl(cidrin.mask);
    }

    n = ngx_atoi(value[1].data, value[1].len);

    var = NULL;
    v = geo->values.elts;

    if (n == NGX_ERROR) {
        for (i = 0; i < geo->values.nelts; i++) {
            if (v[i]->text.len != value[1].len) {
                continue;
            }

            if (ngx_strncmp(value[1].data, v[i]->text.data, value[1].len) == 0)
            {
                var = v[i];
                break;
            }
        }

    } else {
        for (i = 0; i < geo->values.nelts; i++) {
            if (v[i]->value == (ngx_uint_t) n) {
                var = v[i];
                break;
            }
        }
    }

    if (var == NULL) {
        var = ngx_palloc(geo->pool, sizeof(ngx_http_variable_value_t));
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        var->text.len = value[1].len;
        var->text.data = ngx_pstrdup(geo->pool, &value[1]);
        if (var->text.data == NULL) {
            return NGX_CONF_ERROR;
        }

        var->value = (n == NGX_ERROR) ? 0 : n;

        v = ngx_array_push(&geo->values);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }

        *v = var;
    }

    for (i = 2; i; i--) {
        rc = ngx_radix32tree_insert(geo->tree, cidrin.addr, cidrin.mask,
                                    (uintptr_t) var);
        if (rc == NGX_OK) {
            return NGX_CONF_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        /* rc == NGX_BUSY */

        old  = (ngx_http_variable_value_t *)
                    ngx_radix32tree_find(geo->tree, cidrin.addr & cidrin.mask);

        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "duplicate parameter \"%V\", value: \"%V\", "
                           "old value: \"%V\"",
                           &value[0], &var->text, &old->text);

        rc = ngx_radix32tree_delete(geo->tree, cidrin.addr, cidrin.mask);

        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_ERROR;
}
