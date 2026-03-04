
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_eval_loc_conf_s ngx_http_eval_loc_conf_t;


struct ngx_http_eval_loc_conf_s {
    ngx_str_node_t              node;
    ngx_queue_t                 queue;

    ngx_http_eval_loc_conf_t   *parent;

    ngx_http_complex_value_t   *value;

    ngx_rbtree_t                rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 evict;

    ngx_uint_t                  max_cached;
    ngx_uint_t                  cached;
    ngx_msec_t                  valid;

    ngx_pool_t                 *pool;

    void                      **main_conf;
    void                      **srv_conf;
    void                      **loc_conf;

    ngx_msec_t                  expire;
    ngx_file_uniq_t             uniq;
    time_t                      mtime;

    ngx_uint_t                  count;

    ngx_uint_t                  orphan;  /* unsigned  orphan:1; */
};


static ngx_int_t ngx_http_eval_handler(ngx_http_request_t *r);
static ngx_http_eval_loc_conf_t *ngx_http_eval_lookup(ngx_http_request_t *r,
    ngx_str_t *name);
static void ngx_http_eval_evict(ngx_http_eval_loc_conf_t *elcf,
    ngx_http_eval_loc_conf_t *node);
static void ngx_http_eval_node_cleanup(void *data);
static ngx_int_t ngx_http_eval_store(ngx_http_request_t *r,
    ngx_http_eval_loc_conf_t *node);
static ngx_http_eval_loc_conf_t *ngx_http_eval_create_location(
    ngx_http_request_t *r, ngx_str_t *name);
static ngx_int_t ngx_http_eval_read(ngx_http_request_t *r, ngx_pool_t *pool,
    ngx_str_t *name, ngx_buf_t *buf, ngx_file_info_t *fi);
static ngx_int_t ngx_http_eval_set(ngx_http_request_t *r,
    ngx_http_eval_loc_conf_t *node);
static char *ngx_http_eval(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_eval_cleanup(void *data);
static void *ngx_http_eval_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_http_eval_commands[] = {

    { ngx_string("eval"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE1,
      ngx_http_eval,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("eval_cache"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_eval_loc_conf_t, max_cached),
      NULL },

    { ngx_string("eval_cache_valid"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_eval_loc_conf_t, valid),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_eval_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_eval_create_loc_conf,         /* create location configuration */
    ngx_http_eval_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_eval_module = {
    NGX_DYNAMIC_MODULE_V1,
    &ngx_http_eval_module_ctx,             /* module context */
    ngx_http_eval_commands,                /* module directives */
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
ngx_http_eval_handler(ngx_http_request_t *r)
{
    ngx_str_t                    name;
    ngx_http_eval_loc_conf_t    *elcf, *node;
    ngx_http_core_main_conf_t   *cmcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_eval_module);

    if (elcf->value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, elcf->value, &name) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (name.len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    node = ngx_http_eval_lookup(r, &name);

    if (node == NULL) {

        node = ngx_http_eval_create_location(r, &name);
        if (node == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_http_eval_store(r, node) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_http_eval_set(r, node) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->main->count++;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    r->phase_handler = cmcf->phase_engine.server_rewrite_index;

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);

    return NGX_DONE;
}


static ngx_http_eval_loc_conf_t *
ngx_http_eval_lookup(ngx_http_request_t *r, ngx_str_t *name)
{
    uint32_t                   hash;
    ngx_str_t                  filename;
    ngx_msec_t                 now;
    ngx_file_info_t            fi;
    ngx_pool_cleanup_t        *cln;
    ngx_http_eval_loc_conf_t  *elcf, *node;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_eval_module);

    hash = ngx_crc32_long(name->data, name->len);

    node = (ngx_http_eval_loc_conf_t *) ngx_str_rbtree_lookup(&elcf->rbtree,
                                                              name, hash);
    if (node == NULL) {
        return NULL;
    }

    if (name->len >= 5 && ngx_strncmp(name->data, "data:", 5) == 0) {
        goto found;
    }

    now = ngx_current_msec;

    if ((ngx_msec_int_t) (now - node->expire) < 0) {
        goto found;
    }

    filename = *name;

    if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->conf_prefix,
                          &filename)
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_file_info(filename.data, &fi) != NGX_FILE_ERROR
        && ngx_file_uniq(&fi) == node->uniq
        && ngx_file_mtime(&fi) == node->mtime)
    {
        node->expire = now + elcf->valid;
        goto found;
    }

    ngx_http_eval_evict(elcf, node);

    return NULL;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http eval found %p", node);

    cln = ngx_pool_cleanup_add(r->connection->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    ngx_queue_remove(&node->queue);
    ngx_queue_insert_tail(&elcf->evict, &node->queue);

    cln->handler = ngx_http_eval_node_cleanup;
    cln->data = node;

    node->count++;

    return node;
}


static void
ngx_http_eval_evict(ngx_http_eval_loc_conf_t *elcf,
    ngx_http_eval_loc_conf_t *node)
{
    ngx_rbtree_delete(&elcf->rbtree, &node->node.node);
    ngx_queue_remove(&node->queue);

    elcf->cached--;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, node->pool->log, 0,
                   "http eval evict %p n:%ui c:%ui",
                   node, node->count, elcf->cached);

    if (node->count) {
        node->orphan = 1;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, node->pool->log, 0,
                   "http eval free %p", node);

    ngx_destroy_pool(node->pool);
}


static void
ngx_http_eval_node_cleanup(void *data)
{
    ngx_http_eval_loc_conf_t  *node = data;

    node->count--;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, node->pool->log, 0,
                   "http eval cleanup %p n:%ui", node, node->count);

    if (node->count || !node->orphan) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, node->pool->log, 0,
                   "http eval free %p", node);

    ngx_destroy_pool(node->pool);
}


static ngx_int_t
ngx_http_eval_store(ngx_http_request_t *r, ngx_http_eval_loc_conf_t *node)
{
    ngx_msec_t                 now;
    ngx_queue_t               *q;
    ngx_pool_cleanup_t        *cln;
    ngx_http_eval_loc_conf_t  *elcf, *nd;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_eval_module);

    q = ngx_queue_head(&elcf->evict);

    while (elcf->cached + 1 > elcf->max_cached
           && q != ngx_queue_sentinel(&elcf->evict))
    {
        nd = ngx_queue_data(q, ngx_http_eval_loc_conf_t, queue);
        q = ngx_queue_next(q);
        ngx_http_eval_evict(elcf, nd);
    }

    cln = ngx_pool_cleanup_add(r->connection->pool, 0);
    if (cln == NULL) {
        ngx_destroy_pool(node->pool);
        return NGX_ERROR;
    }

    cln->handler = ngx_http_eval_node_cleanup;
    cln->data = node;

    now = ngx_current_msec;

    node->count = 1;
    node->expire = now + elcf->valid;

    if (elcf->max_cached == 0) {
        node->orphan = 1;
        return NGX_OK;
    }

    elcf->cached++;

    ngx_rbtree_insert(&elcf->rbtree, &node->node.node);
    ngx_queue_insert_tail(&elcf->evict, &node->queue);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http eval store %p c:%ui", node, elcf->cached);

    return NGX_OK;
}


static ngx_http_eval_loc_conf_t *
ngx_http_eval_create_location(ngx_http_request_t *r, ngx_str_t *name)
{
    void                       **main_conf, **srv_conf, **loc_conf;
    char                        *rv;
    uint32_t                     hash;
    ngx_buf_t                    buf;
    ngx_log_t                   *log;
    ngx_pool_t                  *pool;
    ngx_uint_t                   i, mi;
    ngx_conf_t                   conf;
    ngx_array_t                  args;
    ngx_module_t               **modules;
    ngx_file_info_t              fi;
    ngx_conf_file_t              conf_file;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t          ctx;
    ngx_http_eval_loc_conf_t    *elcf, *node;
    ngx_http_core_loc_conf_t    *clcf, *pclcf;
    ngx_http_core_main_conf_t   *cmcf;

    log = ngx_cycle->log;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
    if (pool == NULL) {
        return NULL;
    }

    if (ngx_http_eval_read(r, pool, name, &buf, &fi) != NGX_OK) {
        goto failed;
    }

    if (ngx_array_init(&args, pool, 10, sizeof(ngx_str_t)) != NGX_OK) {
        goto failed;
    }

    ngx_memzero(&ctx, sizeof(ngx_http_conf_ctx_t));

    ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));
    conf_file.file.log = log;
    conf_file.line = 1;
    conf_file.file.fd = NGX_INVALID_FILE;
    conf_file.buffer = &buf;

    ngx_memzero(&conf, sizeof(ngx_conf_t));
    conf.ctx = &ctx;
    conf.temp_pool = r->pool;
    conf.cycle = (ngx_cycle_t *) ngx_cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = NGX_HTTP_MODULE;
    conf.cmd_type = NGX_HTTP_LOC_CONF;
    conf.conf_file = &conf_file;
    conf.args = &args;
    conf.dynamic = 1;

    modules = ngx_cycle->modules;

    main_conf = ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module);
    if (main_conf == NULL) {
        goto failed;
    }

    ngx_memcpy(main_conf, r->main_conf, sizeof(void *) * ngx_http_max_module);

    srv_conf = ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module);
    if (srv_conf == NULL) {
        goto failed;
    }

    ngx_memcpy(srv_conf, r->srv_conf, sizeof(void *) * ngx_http_max_module);

    loc_conf = ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module);
    if (loc_conf == NULL) {
        goto failed;
    }

    ngx_memcpy(loc_conf, r->loc_conf, sizeof(void *) * ngx_http_max_module);

    ctx.main_conf = main_conf;
    ctx.srv_conf = srv_conf;
    ctx.loc_conf = loc_conf;

    cmcf = ngx_http_core_recreate_main_conf(&conf);
    if (cmcf == NULL) {
        goto failed;
    }

    main_conf[ngx_http_core_module.ctx_index] = cmcf;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (!(modules[i]->flags & NGX_DYNAMIC_MODULE)) {
            continue;
        }

        mi = modules[i]->ctx_index;
        module = modules[i]->ctx;

        if (module->create_loc_conf) {
            loc_conf[mi] = module->create_loc_conf(&conf);
            if (loc_conf[mi] == NULL) {
                goto failed;
            }
        }
    }

    pclcf = r->loc_conf[ngx_http_core_module.ctx_index];
    clcf = loc_conf[ngx_http_core_module.ctx_index];

    clcf->name = pclcf->name;
    clcf->exact_match = pclcf->exact_match;
    clcf->noregex = pclcf->noregex;
    clcf->named = pclcf->named;
    clcf->dynamic = 1;

    rv = ngx_conf_parse(&conf, &conf_file.file.name);
    if (rv == NGX_CONF_ERROR) {
        goto failed;
    }

    module = ngx_http_core_module.ctx;
    if (module->init_main_conf(&conf, cmcf) != NGX_CONF_OK) {
        goto failed;
    }

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (!(modules[i]->flags & NGX_DYNAMIC_MODULE)) {
            continue;
        }

        mi = modules[i]->ctx_index;
        module = modules[i]->ctx;

        if (module->merge_loc_conf) {
            rv = module->merge_loc_conf(&conf, r->loc_conf[mi], loc_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }

            rv = ngx_http_merge_locations(&conf, clcf->locations, loc_conf,
                                          module, mi);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }
    }

    if (ngx_http_variables_init_vars(&conf) != NGX_OK) {
        goto failed;
    }

    if (ngx_http_init_locations(&conf, NULL, clcf) != NGX_OK) {
        goto failed;
    }

    if (ngx_http_init_static_location_trees(&conf, clcf) != NGX_OK) {
        goto failed;
    }

    node = loc_conf[ngx_http_eval_module.ctx_index];

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_eval_module);

    hash = ngx_crc32_long(name->data, name->len);

    node->node.str.data = ngx_pnalloc(pool, name->len);
    if (node->node.str.data == NULL) {
        goto failed;
    }

    ngx_memcpy(node->node.str.data, name->data, name->len);
    node->node.str.len = name->len;
    node->node.node.key = hash;
    node->pool = pool;
    node->uniq = ngx_file_uniq(&fi);
    node->mtime = ngx_file_mtime(&fi);
    node->parent = elcf;

    node->main_conf = main_conf;
    node->srv_conf = srv_conf;
    node->loc_conf = loc_conf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http eval create %p", node);

    return node;

failed:

    ngx_destroy_pool(pool);

    return NULL;
}


static ngx_int_t
ngx_http_eval_read(ngx_http_request_t *r, ngx_pool_t *pool, ngx_str_t *name,
    ngx_buf_t *buf, ngx_file_info_t *fi)
{
    u_char      *p;
    size_t       size;
    ssize_t      n;
    ngx_fd_t     fd;
    ngx_file_t   file;

    ngx_memzero(buf, sizeof(ngx_buf_t));

    if (name->len >= 5 && ngx_strncmp(name->data, "data:", 5) == 0) {

        buf->pos = name->data + 5;
        buf->last = name->data + name->len;
        buf->start = buf->pos;
        buf->end = buf->last;
        buf->memory = 1;

        ngx_memzero(fi, sizeof(ngx_file_info_t));

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http eval read \"%V\"", name);

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.log = r->connection->log;
    file.name = *name;

    if (ngx_get_full_name(pool, (ngx_str_t *) &ngx_cycle->conf_prefix,
                          &file.name)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name->data);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", name->data);

        (void) ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = (size_t) ngx_file_size(fi);

    p = ngx_pnalloc(pool, size);
    if (p == NULL) {
        (void) ngx_close_file(fd);
        return NGX_ERROR;
    }

    file.fd = fd;

    n = ngx_read_file(&file, p, size, 0);

    if (n == NGX_ERROR) {
        (void) ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                           ngx_read_file_n " returned "
                           "only %z bytes instead of %z", n, size);
        (void) ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_file_n " %s failed", name->data);
        return NGX_ERROR;
    }

    buf->pos = p;
    buf->last = p + size;
    buf->start = buf->pos;
    buf->end = buf->last;
    buf->temporary = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_eval_set(ngx_http_request_t *r, ngx_http_eval_loc_conf_t *node)
{
    ngx_http_variable_value_t  *v;
    ngx_http_core_main_conf_t  *ocmcf, *cmcf;

    ocmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    r->main_conf = node->main_conf;
    r->srv_conf = node->srv_conf;
    r->loc_conf = node->loc_conf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (cmcf->variables.nelts > ocmcf->variables.nelts) {
        v = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                 * sizeof(ngx_http_variable_value_t));
        if (v == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(v, r->variables, ocmcf->variables.nelts
                                    * sizeof(ngx_http_variable_value_t));

        r->variables = v;
    }

    r->realloc_captures = 1;

    /* clear the modules contexts */
    ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);

    ngx_http_update_location_config(r);

    return NGX_OK;
}


static char *
ngx_http_eval(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_eval_loc_conf_t *elcf = conf;

    ngx_str_t                         *value;
    ngx_pool_cleanup_t                *cln;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_compile_complex_value_t   ccv;

    if (elcf->value != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    elcf->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (elcf->value == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = elcf->value;
    ccv.zero = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_eval_handler;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_eval_cleanup;
    cln->data = elcf;

    return NGX_CONF_OK;
}


static void
ngx_http_eval_cleanup(void *data)
{
    ngx_http_eval_loc_conf_t  *elcf = data;

    ngx_queue_t               *q;
    ngx_http_eval_loc_conf_t  *node;

    q = ngx_queue_head(&elcf->evict);

    while (q != ngx_queue_sentinel(&elcf->evict)) {
        node = ngx_queue_data(q, ngx_http_eval_loc_conf_t, queue);
        q = ngx_queue_next(q);

        if (node->count) {
            ngx_log_error(NGX_LOG_ALERT, node->pool->log, 0,
                          "eval node count is non-zero on cleanup");
        }

        ngx_http_eval_evict(elcf, node);
    }
}


static void *
ngx_http_eval_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_eval_loc_conf_t  *elcf;

    elcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_eval_loc_conf_t));
    if (elcf == NULL) {
        return NULL;
    }

    elcf->value = NGX_CONF_UNSET_PTR;
    elcf->max_cached = NGX_CONF_UNSET_UINT;
    elcf->valid = NGX_CONF_UNSET_MSEC;

    ngx_rbtree_init(&elcf->rbtree, &elcf->sentinel,
                    ngx_str_rbtree_insert_value);

    ngx_queue_init(&elcf->evict);

    return elcf;
}


static char *
ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_eval_loc_conf_t *prev = parent;
    ngx_http_eval_loc_conf_t *conf = child;

    ngx_conf_init_ptr_value(conf->value, NULL);

    ngx_conf_merge_uint_value(conf->max_cached, prev->max_cached, 16);

    ngx_conf_merge_msec_value(conf->valid, prev->valid, 100);

    return NGX_CONF_OK;
}
