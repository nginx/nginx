
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_CONDITION_AND     0
#define NGX_HTTP_CONDITION_OR      1

#define NGX_HTTP_CONDITION_VALUE   0
#define NGX_HTTP_CONDITION_EQUAL   1
#define NGX_HTTP_CONDITION_REGEX   2


typedef struct {
    ngx_uint_t                  op;
    ngx_uint_t                  negative;   /* unsigned  negative:1; */

    ngx_http_complex_value_t    left;
    ngx_http_complex_value_t    right;

#if (NGX_PCRE)
    ngx_http_regex_t           *regex;
#endif
} ngx_http_condition_item_t;


typedef struct {
    ngx_array_t                 items;      /* ngx_http_condition_item_t */
    ngx_uint_t                  logical;
} ngx_http_condition_ctx_t;


typedef struct {
    ngx_http_condition_ctx_t   *cond;
    ngx_conf_t                 *cf;
    unsigned                    logical_set:1;
    unsigned                    no_cacheable:1;
} ngx_http_condition_conf_ctx_t;


static char *ngx_http_condition_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_condition(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static char *ngx_http_condition_item(ngx_conf_t *cf,
    ngx_http_condition_conf_ctx_t *ctx);


static ngx_command_t  ngx_http_condition_commands[] = {

    { ngx_string("condition"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_condition_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_condition_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_condition_module = {
    NGX_MODULE_V1,
    &ngx_http_condition_module_ctx,        /* module context */
    ngx_http_condition_commands,           /* module directives */
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


static ngx_int_t
ngx_http_condition_item_value(ngx_http_request_t *r,
    ngx_http_condition_item_t *item, ngx_uint_t *res)
{
    ngx_str_t   left, right;
    ngx_uint_t  value;

    if (ngx_http_complex_value(r, &item->left, &left) != NGX_OK) {
        return NGX_ERROR;
    }

    switch (item->op) {

    case NGX_HTTP_CONDITION_EQUAL:

        if (ngx_http_complex_value(r, &item->right, &right) != NGX_OK) {
            return NGX_ERROR;
        }

        value = (left.len == right.len
                 && ngx_strncmp(left.data, right.data, left.len) == 0);
        break;

#if (NGX_PCRE)
    case NGX_HTTP_CONDITION_REGEX:
        {
        ngx_int_t  rc;

        rc = ngx_http_regex_exec(r, item->regex, &left);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        value = (rc == NGX_OK);
        break;
        }
#endif

    default: /* NGX_HTTP_CONDITION_VALUE */

        value = !(left.len == 0 || (left.len == 1 && left.data[0] == '0'));
        break;
    }

    if (item->negative) {
        value = !value;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http condition item: \"%V\":%ui", &left, value);

    *res = value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_condition_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_condition_ctx_t  *cond = (ngx_http_condition_ctx_t *) data;

    ngx_uint_t                  i, value, res;
    ngx_http_condition_item_t  *item;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http condition started");

    res = (cond->logical == NGX_HTTP_CONDITION_AND);

    item = cond->items.elts;

    for (i = 0; i < cond->items.nelts; i++) {

        if (ngx_http_condition_item_value(r, &item[i], &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (cond->logical == NGX_HTTP_CONDITION_AND) {

            if (!value) {
                res = 0;
                break;
            }

        } else {

            if (value) {
                res = 1;
                break;
            }
        }
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (res) {
        v->len = 1;
        v->data = (u_char *) "1";

    } else {
        v->len = 0;
        v->data = (u_char *) "";
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http condition: \"%v\"", v);

    return NGX_OK;
}


static char *
ngx_http_condition_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                           *rv;
    ngx_str_t                      *value, name;
    ngx_conf_t                      save;
    ngx_http_variable_t            *var;
    ngx_http_condition_ctx_t       *cond;
    ngx_http_condition_conf_ctx_t   ctx;

    cond = ngx_pcalloc(cf->pool, sizeof(ngx_http_condition_ctx_t));
    if (cond == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cond->items, cf->pool, 4,
                       sizeof(ngx_http_condition_item_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    name = value[1];

    if (name.len < 2 || name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_condition_variable;
    var->data = (uintptr_t) cond;

    ngx_memzero(&ctx, sizeof(ngx_http_condition_conf_ctx_t));

    ctx.cond = cond;
    ctx.cf = &save;

    save = *cf;
    cf->ctx = &ctx;
    cf->handler = ngx_http_condition;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!ctx.logical_set) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no \"and\" or \"or\" parameter "
                           "in \"condition\" block");
        return NGX_CONF_ERROR;
    }

    if (ctx.no_cacheable) {
        var->flags |= NGX_HTTP_VAR_NOCACHEABLE;
    }

    return rv;
}


static char *
ngx_http_condition(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_str_t                      *value;
    ngx_http_condition_conf_ctx_t  *ctx;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {

        if (ngx_strcmp(value[0].data, "and") == 0
            || ngx_strcmp(value[0].data, "or") == 0)
        {
            if (ctx->logical_set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate \"%V\" parameter", &value[0]);
                return NGX_CONF_ERROR;
            }

            ctx->cond->logical = (value[0].data[0] == 'a')
                                 ? NGX_HTTP_CONDITION_AND
                                 : NGX_HTTP_CONDITION_OR;
            ctx->logical_set = 1;

            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[0].data, "volatile") == 0) {
            ctx->no_cacheable = 1;
            return NGX_CONF_OK;
        }
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "include") == 0) {
        return ngx_conf_include(cf, dummy, conf);
    }

    return ngx_http_condition_item(cf, ctx);
}


static char *
ngx_http_condition_item(ngx_conf_t *cf, ngx_http_condition_conf_ctx_t *ctx)
{
    u_char                            *p;
    size_t                             len;
    ngx_str_t                         *value;
    ngx_http_condition_item_t         *item;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (cf->args->nelts != 1 && cf->args->nelts != 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of the condition parameters");
        return NGX_CONF_ERROR;
    }

    item = ngx_array_push(&ctx->cond->items);
    if (item == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(item, sizeof(ngx_http_condition_item_t));

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = ctx->cf;
    ccv.value = &value[0];
    ccv.complex_value = &item->left;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 1) {
        item->op = NGX_HTTP_CONDITION_VALUE;
        return NGX_CONF_OK;
    }

    len = value[1].len;
    p = value[1].data;

    if ((len == 1 && p[0] == '=')
        || (len == 2 && p[0] == '!' && p[1] == '='))
    {
        item->op = NGX_HTTP_CONDITION_EQUAL;
        item->negative = (p[0] == '!');

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = ctx->cf;
        ccv.value = &value[2];
        ccv.complex_value = &item->right;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if ((len == 1 && p[0] == '~')
        || (len == 2 && p[0] == '~' && p[1] == '*')
        || (len == 2 && p[0] == '!' && p[1] == '~')
        || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
    {
#if (NGX_PCRE)
        ngx_regex_compile_t  rc;
        u_char               errstr[NGX_MAX_CONF_ERRSTR];

        item->op = NGX_HTTP_CONDITION_REGEX;
        item->negative = (p[0] == '!');

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = value[2];
        rc.options = (p[len - 1] == '*') ? NGX_REGEX_CASELESS : 0;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        item->regex = ngx_http_regex_compile(ctx->cf, &rc);
        if (item->regex == NULL) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "using regex \"%V\" requires PCRE library",
                           &value[2]);
        return NGX_CONF_ERROR;
#endif
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unexpected \"%V\" in condition", &value[1]);

    return NGX_CONF_ERROR;
}
