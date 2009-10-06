
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_char              color;
    u_char              len;
    u_short             conn;
    u_char              data[1];
} ngx_http_limit_zone_node_t;


typedef struct {
    ngx_shm_zone_t     *shm_zone;
    ngx_rbtree_node_t  *node;
} ngx_http_limit_zone_cleanup_t;


typedef struct {
    ngx_rbtree_t       *rbtree;
    ngx_int_t           index;
    ngx_str_t           var;
} ngx_http_limit_zone_ctx_t;


typedef struct {
    ngx_shm_zone_t     *shm_zone;
    ngx_uint_t          conn;
    ngx_uint_t          log_level;
} ngx_http_limit_zone_conf_t;


static void ngx_http_limit_zone_cleanup(void *data);

static void *ngx_http_limit_zone_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_zone_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_zone_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_limit_zone_commands[] = {

    { ngx_string("limit_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_conn"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_conn_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_zone_conf_t, log_level),
      &ngx_http_limit_conn_log_levels },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_zone_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_zone_create_conf,       /* create location configration */
    ngx_http_limit_zone_merge_conf         /* merge location configration */
};


ngx_module_t  ngx_http_limit_zone_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_zone_module_ctx,       /* module context */
    ngx_http_limit_zone_commands,          /* module directives */
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
ngx_http_limit_zone_handler(ngx_http_request_t *r)
{
    size_t                          len, n;
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_pool_cleanup_t             *cln;
    ngx_http_variable_value_t      *vv;
    ngx_http_limit_zone_ctx_t      *ctx;
    ngx_http_limit_zone_node_t     *lz;
    ngx_http_limit_zone_conf_t     *lzcf;
    ngx_http_limit_zone_cleanup_t  *lzcln;

    if (r->main->limit_zone_set) {
        return NGX_DECLINED;
    }

    lzcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_zone_module);

    if (lzcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = lzcf->shm_zone->data;

    vv = ngx_http_get_indexed_variable(r, ctx->index);

    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    len = vv->len;

    if (len == 0) {
        return NGX_DECLINED;
    }

    if (len > 255) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the value of the \"%V\" variable "
                      "is more than 255 bytes: \"%v\"",
                      &ctx->var, vv);
        return NGX_DECLINED;
    }

    r->main->limit_zone_set = 1;

    hash = ngx_crc32_short(vv->data, len);

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_limit_zone_cleanup_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    shpool = (ngx_slab_pool_t *) lzcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = ctx->rbtree->root;
    sentinel = ctx->rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        do {
            lz = (ngx_http_limit_zone_node_t *) &node->color;

            rc = ngx_memn2cmp(vv->data, lz->data, len, (size_t) lz->len);

            if (rc == 0) {
                if ((ngx_uint_t) lz->conn < lzcf->conn) {
                    lz->conn++;
                    goto done;
                }

                ngx_shmtx_unlock(&shpool->mutex);

                ngx_log_error(lzcf->log_level, r->connection->log, 0,
                              "limiting connections by zone \"%V\"",
                              &lzcf->shm_zone->shm.name);

                return NGX_HTTP_SERVICE_UNAVAILABLE;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_limit_zone_node_t, data)
        + len;

    node = ngx_slab_alloc_locked(shpool, n);
    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    lz = (ngx_http_limit_zone_node_t *) &node->color;

    node->key = hash;
    lz->len = (u_char) len;
    lz->conn = 1;
    ngx_memcpy(lz->data, vv->data, len);

    ngx_rbtree_insert(ctx->rbtree, node);

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit zone: %08XD %d", node->key, lz->conn);

    ngx_shmtx_unlock(&shpool->mutex);

    cln->handler = ngx_http_limit_zone_cleanup;
    lzcln = cln->data;

    lzcln->shm_zone = lzcf->shm_zone;
    lzcln->node = node;

    return NGX_DECLINED;
}


static void
ngx_http_limit_zone_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_limit_zone_node_t   *lzn, *lznt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lzn = (ngx_http_limit_zone_node_t *) &node->color;
            lznt = (ngx_http_limit_zone_node_t *) &temp->color;

            p = (ngx_memn2cmp(lzn->data, lznt->data, lzn->len, lznt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_http_limit_zone_cleanup(void *data)
{
    ngx_http_limit_zone_cleanup_t  *lzcln = data;

    ngx_slab_pool_t             *shpool;
    ngx_rbtree_node_t           *node;
    ngx_http_limit_zone_ctx_t   *ctx;
    ngx_http_limit_zone_node_t  *lz;

    ctx = lzcln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lzcln->shm_zone->shm.addr;
    node = lzcln->node;
    lz = (ngx_http_limit_zone_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lzcln->shm_zone->shm.log, 0,
                   "limit zone cleanup: %08XD %d", node->key, lz->conn);

    lz->conn--;

    if (lz->conn == 0) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}


static ngx_int_t
ngx_http_limit_zone_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_zone_ctx_t  *octx = data;

    size_t                      len;
    ngx_slab_pool_t            *shpool;
    ngx_rbtree_node_t          *sentinel;
    ngx_http_limit_zone_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ngx_strcmp(ctx->var.data, octx->var.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_zone \"%V\" uses the \"%V\" variable "
                          "while previously it used the \"%V\" variable",
                          &shm_zone->shm.name, &ctx->var, &octx->var);
            return NGX_ERROR;
        }

        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_limit_zone_rbtree_insert_value);

    len = sizeof(" in limit_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in limit_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_http_limit_zone_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_zone_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_zone_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->shm_zone = NULL;
     *     conf->conn = 0;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_limit_zone_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_zone_conf_t *prev = parent;
    ngx_http_limit_zone_conf_t *conf = child;

    if (conf->shm_zone == NULL) {
        *conf = *prev;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                     n;
    ngx_str_t                  *value;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_limit_zone_ctx_t  *ctx;

    value = cf->args->elts;

    if (value[2].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    value[2].len--;
    value[2].data++;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_zone_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->index = ngx_http_get_variable_index(cf, &value[2]);
    if (ctx->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    ctx->var = value[2];

    n = ngx_parse_size(&value[3]);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid size of limit_zone \"%V\"", &value[3]);
        return NGX_CONF_ERROR;
    }

    if (n < (ngx_int_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "limit_zone \"%V\" is too small", &value[1]);
        return NGX_CONF_ERROR;
    }


    shm_zone = ngx_shared_memory_add(cf, &value[1], n,
                                     &ngx_http_limit_zone_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "limit_zone \"%V\" is already bound to variable \"%V\"",
                        &value[1], &ctx->var);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_limit_zone_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_zone_conf_t  *lzcf = conf;

    ngx_int_t   n;
    ngx_str_t  *value;

    if (lzcf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lzcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                           &ngx_http_limit_zone_module);
    if (lzcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    n = ngx_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (n > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NGX_CONF_ERROR;
    }

    lzcf->conn = n;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_zone_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_zone_handler;

    return NGX_OK;
}
