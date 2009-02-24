
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_short                          start;
    u_short                          end;
    ngx_http_variable_value_t       *value;
} ngx_http_geo_range_t;


typedef struct {
    ngx_http_geo_range_t            *ranges;
    ngx_uint_t                       n;
} ngx_http_geo_low_ranges_t;


typedef struct {
    ngx_http_geo_low_ranges_t        low[0x10000];
    ngx_http_variable_value_t       *default_value;
} ngx_http_geo_high_ranges_t;


typedef struct {
    ngx_http_variable_value_t       *value;
    ngx_str_t                       *net;
    ngx_http_geo_high_ranges_t      *high;
    ngx_radix_tree_t                *tree;
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_pool_t                      *pool;
    ngx_pool_t                      *temp_pool;
} ngx_http_geo_conf_ctx_t;


typedef struct {
    union {
        ngx_radix_tree_t            *tree;
        ngx_http_geo_high_ranges_t  *high;
    } u;

    ngx_int_t                        index;
} ngx_http_geo_ctx_t;


static in_addr_t ngx_http_geo_addr(ngx_http_request_t *r,
    ngx_http_geo_ctx_t *ctx);
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
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
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
    ngx_http_geo_ctx_t *ctx = (ngx_http_geo_ctx_t *) data;

    ngx_http_variable_value_t  *vv;

    vv = (ngx_http_variable_value_t *)
              ngx_radix32tree_find(ctx->u.tree, ngx_http_geo_addr(r, ctx));

    *v = *vv;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo: %v", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_geo_range_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_geo_ctx_t *ctx = (ngx_http_geo_ctx_t *) data;

    in_addr_t              addr;
    ngx_uint_t             i, n;
    ngx_http_geo_range_t  *range;

    *v = *ctx->u.high->default_value;

    addr = ngx_http_geo_addr(r, ctx);

    range = ctx->u.high->low[addr >> 16].ranges;

    n = addr & 0xffff;

    for (i = 0; i < ctx->u.high->low[addr >> 16].n; i++) {
        if (n >= (ngx_uint_t) range[i].start
            && n <= (ngx_uint_t) range[i].end)
        {
            *v = *range[i].value;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo: %v", v);

    return NGX_OK;
}


static in_addr_t
ngx_http_geo_addr(ngx_http_request_t *r, ngx_http_geo_ctx_t *ctx)
{
    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *v;

    if (ctx->index == -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http geo started: %V", &r->connection->addr_text);

        if (r->connection->sockaddr->sa_family != AF_INET) {
            return 0;
        }

        sin = (struct sockaddr_in *) r->connection->sockaddr;
        return ntohl(sin->sin_addr.s_addr);
    }

    v = ngx_http_get_flushed_variable(r, ctx->index);

    if (v == NULL || v->not_found) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http geo not found");

        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http geo started: %v", v);

    return ntohl(ngx_inet_addr(v->data, v->len));
}


static char *
ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    size_t                    len;
    ngx_str_t                *value, name;
    ngx_uint_t                i;
    ngx_conf_t                save;
    ngx_pool_t               *pool;
    ngx_array_t              *a;
    ngx_http_variable_t      *var;
    ngx_http_geo_ctx_t       *geo;
    ngx_http_geo_conf_ctx_t   ctx;

    value = cf->args->elts;

    geo = ngx_palloc(cf->pool, sizeof(ngx_http_geo_ctx_t));
    if (geo == NULL) {
        return NGX_CONF_ERROR;
    }

    name = value[1];
    name.len--;
    name.data++;

    if (cf->args->nelts == 3) {

        geo->index = ngx_http_get_variable_index(cf, &name);
        if (geo->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        name = value[2];
        name.len--;
        name.data++;

    } else {
        geo->index = -1;
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

        geo->u.high = ctx.high;

        var->get_handler = ngx_http_geo_range_variable;
        var->data = (uintptr_t) geo;

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

        geo->u.tree = ctx.tree;

        var->get_handler = ngx_http_geo_cidr_variable;
        var->data = (uintptr_t) geo;

        ngx_destroy_pool(ctx.temp_pool);
        ngx_destroy_pool(pool);

        if (ngx_radix32tree_find(ctx.tree, 0) != NGX_RADIX_NO_VALUE) {
            return rv;
        }

        if (ngx_radix32tree_insert(ctx.tree, 0, 0,
                                   (uintptr_t) &ngx_http_variable_null_value)
            == NGX_ERROR)
        {
            return NGX_CONF_ERROR;
        }
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

    for (n = start; n <= end; n += 0x10000) {

        h = n >> 16;

        if (n == start) {
            s = n & 0xffff;
        } else {
            s = 0;
        }

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

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                goto next;
            }

            if (s == (ngx_uint_t) range[i].start
                && e == (ngx_uint_t) range[i].end)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    ctx->net, ctx->value, range[i].value);

                range[i].value = ctx->value;

                goto next;
            }

            if (s > (ngx_uint_t) range[i].start
                && e < (ngx_uint_t) range[i].end)
            {
                /* split the range and insert the new one */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memcpy(&range[i + 3], &range[i + 1],
                           (a->nelts - 3 - i) * sizeof(ngx_http_geo_range_t));

                range[i + 2].start = (u_short) (e + 1);
                range[i + 2].end = range[i].end;
                range[i + 2].value = range[i].value;

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            if (s == (ngx_uint_t) range[i].start
                && e < (ngx_uint_t) range[i].end)
            {
                /* shift the range start and insert the new range */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memcpy(&range[i + 1], &range[i],
                           (a->nelts - 1 - i) * sizeof(ngx_http_geo_range_t));

                range[i + 1].start = (u_short) (e + 1);

                range[i].start = (u_short) s;
                range[i].end = (u_short) e;
                range[i].value = ctx->value;

                goto next;
            }

            if (s > (ngx_uint_t) range[i].start
                && e == (ngx_uint_t) range[i].end)
            {
                /* shift the range end and insert the new range */

                range = ngx_array_push(a);
                if (range == NULL) {
                    return NGX_CONF_ERROR;
                }

                range = a->elts;

                ngx_memcpy(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(ngx_http_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            s = (ngx_uint_t) range[i].start;
            e = (ngx_uint_t) range[i].end;

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "range \"%V\" overlaps \"%d.%d.%d.%d-%d.%d.%d.%d\"",
                         ctx->net,
                         h >> 8, h & 0xff, s >> 8, s & 0xff,
                         h >> 8, h & 0xff, e >> 8, e & 0xff);

            return NGX_CONF_ERROR;
        }

        /* add the first range */

        range = ngx_array_push(a);
        if (range == NULL) {
            return NGX_CONF_ERROR;
        }

        range->start = (u_short) s;
        range->end = (u_short) e;
        range->value = ctx->value;

    next:

        continue;
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

    for (n = start; n <= end; n += 0x10000) {

        h = n >> 16;

        if (n == start) {
            s = n & 0xffff;
        } else {
            s = 0;
        }

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

                a->nelts--;

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
    ngx_cidr_t                       cidr;
    ngx_http_variable_value_t       *val, *old;

    if (ctx->tree == NULL) {
        ctx->tree = ngx_radix_tree_create(ctx->pool, -1);
        if (ctx->tree == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_strcmp(value[0].data, "default") == 0) {
        cidr.u.in.addr = 0;
        cidr.u.in.mask = 0;
        net = &value[0];

    } else {
        if (ngx_strcmp(value[0].data, "delete") == 0) {
            net = &value[1];
            del = 1;

        } else {
            net = &value[0];
            del = 0;
        }

        if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
            cidr.u.in.addr = 0xffffffff;
            cidr.u.in.mask = 0xffffffff;

        } else {
            rc = ngx_ptocidr(net, &cidr);

            if (rc == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid network \"%V\"", net);
                return NGX_CONF_ERROR;
            }

            if (cidr.family != AF_INET) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "\"geo\" supports IPv4 only");
                return NGX_CONF_ERROR;
            }

            if (rc == NGX_DONE) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "low address bits of %V are meaningless",
                                   net);
            }

            cidr.u.in.addr = ntohl(cidr.u.in.addr);
            cidr.u.in.mask = ntohl(cidr.u.in.mask);
        }

        if (del) {
            if (ngx_radix32tree_delete(ctx->tree, cidr.u.in.addr,
                                       cidr.u.in.mask)
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
        rc = ngx_radix32tree_insert(ctx->tree, cidr.u.in.addr, cidr.u.in.mask,
                                    (uintptr_t) val);
        if (rc == NGX_OK) {
            return NGX_CONF_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        /* rc == NGX_BUSY */

        old  = (ngx_http_variable_value_t *)
              ngx_radix32tree_find(ctx->tree, cidr.u.in.addr & cidr.u.in.mask);

        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
                net, val, old);

        rc = ngx_radix32tree_delete(ctx->tree, cidr.u.in.addr, cidr.u.in.mask);

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
