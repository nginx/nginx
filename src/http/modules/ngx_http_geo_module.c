
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_short                      start;
    u_short                      end;
    ngx_http_variable_value_t   *value;
} ngx_http_geo_range_t;


typedef struct {
    ngx_http_geo_range_t        *ranges;
    ngx_uint_t                   n;
} ngx_http_geo_low_ranges_t;


typedef struct {
    ngx_http_geo_low_ranges_t    low[0x10000];
    ngx_http_variable_value_t   *default_value;
} ngx_http_geo_high_ranges_t;


typedef struct {
    ngx_http_variable_value_t   *value;
    ngx_str_t                   *net;
    ngx_http_geo_high_ranges_t  *high;
    ngx_radix_tree_t            *tree;
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_pool_t                  *pool;
    ngx_pool_t                  *temp_pool;
} ngx_http_geo_conf_ctx_t;


static char *ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char *ngx_http_geo_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    ngx_str_t *value);
static char *ngx_http_geo_add_range(ngx_conf_t *cf,
    ngx_http_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static ngx_uint_t ngx_http_geo_delete_range(ngx_conf_t *cf,
    ngx_http_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static char *ngx_http_geo_cidr(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    ngx_str_t *value);
static ngx_http_variable_value_t *ngx_http_geo_value(ngx_conf_t *cf,
    ngx_http_geo_conf_ctx_t *ctx, ngx_str_t *value);


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
ngx_http_geo_cidr_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_radix_tree_t *tree = (ngx_radix_tree_t *) data;

    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *vv;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo started");

    sin = (struct sockaddr_in *) r->connection->sockaddr;

    vv = (ngx_http_variable_value_t *)
                       ngx_radix32tree_find(tree, ntohl(sin->sin_addr.s_addr));

    *v = *vv;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo: %V %v", &r->connection->addr_text, v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_geo_range_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_geo_high_ranges_t *high = (ngx_http_geo_high_ranges_t *) data;

    in_addr_t              addr;
    ngx_uint_t             i, n;
    struct sockaddr_in    *sin;
    ngx_http_geo_range_t  *range;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo started");

    sin = (struct sockaddr_in *) r->connection->sockaddr;

    *v = *high->default_value;

    addr = ntohl(sin->sin_addr.s_addr);

    range = high->low[addr >> 16].ranges;

    n = addr & 0xffff;

    for (i = 0; i < high->low[addr >> 16].n; i++) {
        if (n >= (ngx_uint_t) range[i].start
            && n <= (ngx_uint_t) range[i].end)
        {
            *v = *range[i].value;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo: %V %v", &r->connection->addr_text, v);

    return NGX_OK;
}


static char *
ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    size_t                    len;
    ngx_str_t                *value, name;
    ngx_uint_t                i, count;
    ngx_conf_t                save;
    ngx_pool_t               *pool;
    ngx_array_t              *a;
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

    pool = ngx_create_pool(16384, cf->log);
    if (pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx.temp_pool = ngx_create_pool(16384, cf->log);
    if (ctx.temp_pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_rbtree_init(&ctx.rbtree, &ctx.sentinel,
                    ngx_http_variable_value_rbtree_insert);

    ctx.high = NULL;
    ctx.tree = NULL;
    ctx.pool = cf->pool;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = ngx_http_geo;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (ctx.high) {

        for (i = 0; i < 0x10000; i++) {
            a = (ngx_array_t *) ctx.high->low[i].ranges;

            if (a == NULL || a->nelts == 0) {
                continue;
            }

            ctx.high->low[i].n = a->nelts;

            len = a->nelts * sizeof(ngx_http_geo_range_t);

            ctx.high->low[i].ranges = ngx_palloc(cf->pool, len);
            if (ctx.high->low[i].ranges == NULL ){
                return NGX_CONF_ERROR;
            }

            ngx_memcpy(ctx.high->low[i].ranges, a->elts, len);
        }

        var->get_handler = ngx_http_geo_range_variable;
        var->data = (uintptr_t) ctx.high;

        ngx_destroy_pool(ctx.temp_pool);
        ngx_destroy_pool(pool);

        if (ctx.high->default_value == NULL) {
            ctx.high->default_value = &ngx_http_variable_null_value;
        }

    } else {
        if (ctx.tree == NULL) {
            ctx.tree = ngx_radix_tree_create(cf->pool, -1);
            if (ctx.tree == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        var->get_handler = ngx_http_geo_cidr_variable;
        var->data = (uintptr_t) ctx.tree;

        ngx_destroy_pool(ctx.temp_pool);
        ngx_destroy_pool(pool);

        if (ngx_radix32tree_find(ctx.tree, 0) == NGX_RADIX_NO_VALUE) {

            if (ngx_radix32tree_insert(ctx.tree, 0, 0,
                                     (uintptr_t) &ngx_http_variable_null_value)
                == NGX_ERROR)
            {
                return NGX_CONF_ERROR;
            }
        }

        count = ctx.tree->count;

        ngx_radix32tree_compress(ctx.tree);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                      "\"%V\" geo tree has been compressed as %ui/%ui",
                      &name, ctx.tree->count, count);
    }

    return rv;
}


static char *
ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    char                     *rv;
    ngx_str_t                *value, file;
    ngx_http_geo_conf_ctx_t  *ctx;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {

        if (ngx_strcmp(value[0].data, "ranges") == 0) {

            if (ctx->tree) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"ranges\" directive must be "
                                   "the first directive inside \"geo\" block");
                goto failed;
            }

            ctx->high = ngx_pcalloc(ctx->pool,
                                    sizeof(ngx_http_geo_high_ranges_t));
            if (ctx->high == NULL) {
                goto failed;
            }

            rv = NGX_CONF_OK;

            goto done;
        }
    }

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of the geo parameters");
        goto failed;
    }

    if (ngx_strcmp(value[0].data, "include") == 0) {

        file.len = value[1].len++;

        file.data = ngx_pstrdup(ctx->temp_pool, &value[1]);
        if (file.data == NULL) {
            goto failed;
        }

        if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK){
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        rv = ngx_conf_parse(cf, &file);

        goto done;
    }

    if (ctx->high) {
        rv = ngx_http_geo_range(cf, ctx, value);

    } else {
        rv = ngx_http_geo_cidr(cf, ctx, value);
    }

done:

    ngx_reset_pool(cf->pool);

    return rv;

failed:

    ngx_reset_pool(cf->pool);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_geo_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    ngx_str_t *value)
{
    u_char                     *p, *last;
    in_addr_t                   start, end;
    ngx_str_t                  *net;
    ngx_uint_t                  del;
    ngx_http_variable_value_t  *old;

    if (ngx_strcmp(value[0].data, "default") == 0) {

        old = ctx->high->default_value;

        ctx->high->default_value = ngx_http_geo_value(cf, ctx, &value[1]);
        if (ctx->high->default_value == NULL) {
            return NGX_CONF_ERROR;
        }

        if (old) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    &value[0], ctx->high->default_value, old);
        }

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    last = net->data + net->len;

    p = ngx_strlchr(net->data, last, '-');

    if (p == NULL) {
        goto invalid;
    }

    start = ngx_inet_addr(net->data, p - net->data);

    if (start == INADDR_NONE) {
        goto invalid;
    }

    start = ntohl(start);

    p++;

    end = ngx_inet_addr(p, last - p);

    if (end == INADDR_NONE) {
        goto invalid;
    }

    end = ntohl(end);

    if (start > end) {
        goto invalid;
    }

    if (del) {
        if (ngx_http_geo_delete_range(cf, ctx, start, end)) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "no address range \"%V\" to delete", net);
        }

        return NGX_CONF_OK;
    }

    ctx->value = ngx_http_geo_value(cf, ctx, &value[1]);

    if (ctx->value == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->net = net;

    return ngx_http_geo_add_range(cf, ctx, start, end);

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);

    return NGX_CONF_ERROR;
}


/* the add procedure is optimized to add a growing up sequence */

static char *
ngx_http_geo_add_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t              n;
    ngx_uint_t             h, i, s, e;
    ngx_array_t           *a;
    ngx_http_geo_range_t  *range;

    for (n = start; n < end; n += 0x10000) {

        h = n >> 16;
        s = n & 0xffff;

        if ((n | 0xffff) > end) {
            e = end & 0xffff;

        } else {
            e = 0xffff;
        }

        a = (ngx_array_t *) ctx->high->low[h].ranges;

        if (a == NULL) {
            a = ngx_array_create(ctx->temp_pool, 64,
                                 sizeof(ngx_http_geo_range_t));
            if (a == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->high->low[h].ranges = (ngx_http_geo_range_t *) a;
        }

        i = a->nelts;
        range = a->elts;

        while (i) {

            i--;

            if (e < (ngx_uint_t) range[i].start) {
                continue;
            }

            if (s > (ngx_uint_t) range[i].end) {

                /* add after the range */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memcpy(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(ngx_http_geo_range_t));

                range = &range[i + 1];

                goto next;
            }

            if (s == (ngx_uint_t) range[i].start
                && e == (ngx_uint_t) range[i].end)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    ctx->net, ctx->value, range[i].value);
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "overlapped range \"%V\"", ctx->net);

            return NGX_CONF_ERROR;
        }

        /* add the first range */

        range = ngx_array_push(a);
        if (range == NULL) {
            return NGX_CONF_ERROR;
        }

    next:

        range->start = (u_short) s;
        range->end = (u_short) e;
        range->value = ctx->value;
    }

    return NGX_CONF_OK;
}


static ngx_uint_t
ngx_http_geo_delete_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t              n;
    ngx_uint_t             h, i, s, e, warn;
    ngx_array_t           *a;
    ngx_http_geo_range_t  *range;

    warn = 0;

    for (n = start; n < end; n += 0x10000) {

        h = n >> 16;
        s = n & 0xffff;

        if ((n | 0xffff) > end) {
            e = end & 0xffff;

        } else {
            e = 0xffff;
        }

        a = (ngx_array_t *) ctx->high->low[h].ranges;

        if (a == NULL) {
            warn = 1;
            continue;
        }

        range = a->elts;
        for (i = 0; i < a->nelts; i++) {

            if (s == (ngx_uint_t) range[i].start
                && e == (ngx_uint_t) range[i].end)
            {
                ngx_memcpy(&range[i], &range[i + 1],
                           (a->nelts - 1 - i) * sizeof(ngx_http_geo_range_t));
                break;
            }

            if (s != (ngx_uint_t) range[i].start
                && e != (ngx_uint_t) range[i].end)
            {
                continue;
            }

            warn = 1;
        }
    }

    return warn;
}


static char *
ngx_http_geo_cidr(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    ngx_str_t *value)
{
    ngx_int_t                        rc, del;
    ngx_str_t                       *net;
    ngx_uint_t                       i;
    ngx_inet_cidr_t                  cidrin;
    ngx_http_variable_value_t       *val, *old;

    if (ctx->tree == NULL) {
        ctx->tree = ngx_radix_tree_create(ctx->pool, -1);
        if (ctx->tree == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_strcmp(value[0].data, "default") == 0) {
        cidrin.addr = 0;
        cidrin.mask = 0;
        net = &value[0];

    } else {
        if (ngx_strcmp(value[0].data, "delete") == 0) {
            net = &value[1];
            del = 1;

        } else {
            net = &value[0];
            del = 0;
        }

        rc = ngx_ptocidr(net, &cidrin);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid network \"%V\"", net);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless", net);
        }

        cidrin.addr = ntohl(cidrin.addr);
        cidrin.mask = ntohl(cidrin.mask);

        if (del) {
            if (ngx_radix32tree_delete(ctx->tree, cidrin.addr, cidrin.mask)
                != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "no network \"%V\" to delete", net);
            }

            return NGX_CONF_OK;
        }
    }

    val = ngx_http_geo_value(cf, ctx, &value[1]);

    if (val == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i; i--) {
        rc = ngx_radix32tree_insert(ctx->tree, cidrin.addr, cidrin.mask,
                                    (uintptr_t) val);
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
                "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
                net, val, old);

        rc = ngx_radix32tree_delete(ctx->tree, cidrin.addr, cidrin.mask);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid radix tree");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_ERROR;
}


static ngx_http_variable_value_t *
ngx_http_geo_value(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
    ngx_str_t *value)
{
    uint32_t                         hash;
    ngx_http_variable_value_t       *val;
    ngx_http_variable_value_node_t  *vvn;

    hash = ngx_crc32_long(value->data, value->len);

    val = ngx_http_variable_value_lookup(&ctx->rbtree, value, hash);

    if (val) {
        return val;
    }

    val = ngx_palloc(ctx->pool, sizeof(ngx_http_variable_value_t));
    if (val == NULL) {
        return NULL;
    }

    val->len = value->len;
    val->data = ngx_pstrdup(ctx->pool, value);
    if (val->data == NULL) {
        return NULL;
    }

    val->valid = 1;
    val->no_cacheable = 0;
    val->not_found = 0;

    vvn = ngx_palloc(ctx->temp_pool, sizeof(ngx_http_variable_value_node_t));
    if (vvn == NULL) {
        return NULL;
    }

    vvn->node.key = hash;
    vvn->len = val->len;
    vvn->value = val;

    ngx_rbtree_insert(&ctx->rbtree, &vvn->node);

    return val;
}
