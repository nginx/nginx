
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t             indices;
    size_t                  max_index_len;
    ngx_http_cache_hash_t  *index_cache;
} ngx_http_index_loc_conf_t;


typedef struct {
    ngx_uint_t         index;
    u_char            *last;
    ngx_str_t          path;
    ngx_str_t          redirect;
    ngx_http_cache_t  *cache;
    unsigned           tested:1;
} ngx_http_index_ctx_t;


#define NGX_HTTP_DEFAULT_INDEX   "index.html"


static ngx_int_t ngx_http_index_test_dir(ngx_http_request_t *r,
                                         ngx_http_index_ctx_t *ctx);
static ngx_int_t ngx_http_index_error(ngx_http_request_t *r,
                                      ngx_http_index_ctx_t *ctx, ngx_err_t err);

static ngx_int_t ngx_http_index_init(ngx_cycle_t *cycle);
static void *ngx_http_index_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_index_merge_loc_conf(ngx_conf_t *cf,
                                       void *parent, void *child);
static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf);


static ngx_command_t  ngx_http_index_commands[] = {

    { ngx_string("index"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_index_set_index,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#if (NGX_HTTP_CACHE)

    { ngx_string("index_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_set_cache_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_index_loc_conf_t, index_cache),
      NULL },

#endif

      ngx_null_command
};


ngx_http_module_t  ngx_http_index_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_index_create_loc_conf,        /* create location configration */
    ngx_http_index_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_index_module = {
    NGX_MODULE,
    &ngx_http_index_module_ctx,            /* module context */
    ngx_http_index_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_index_init,                   /* init module */
    NULL                                   /* init child */
};


/*
 * Try to open the first index file before the test of the directory existence
 * because the valid requests should be many more than invalid ones.
 * If open() failed then stat() should be more quickly because some data
 * is already cached in the kernel.
 * Besides Win32 has ERROR_PATH_NOT_FOUND (NGX_ENOTDIR).
 * Unix has ENOTDIR error, although it less helpfull - it shows only
 * that path contains the usual file in place of the directory.
 */

ngx_int_t ngx_http_index_handler(ngx_http_request_t *r)
{
    u_char                     *name;
    ngx_fd_t                    fd;
    ngx_int_t                   rc;
    ngx_str_t                  *index;
    ngx_err_t                   err;
    ngx_log_t                  *log;
    ngx_http_index_ctx_t       *ctx;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_index_loc_conf_t  *ilcf;
#if (NGX_HTTP_CACHE0)
    /* crc must be in ctx !! */
    uint32_t                    crc;
#endif

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    /*
     * we use context because the handler supports an async file opening
     * and thus can be called several times
     */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_index_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_index_module);
    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_index_module,
                            sizeof(ngx_http_index_ctx_t),
                            NGX_HTTP_INTERNAL_SERVER_ERROR);

#if (NGX_HTTP_CACHE)

        if (ilcf->index_cache) {
            ctx->cache = ngx_http_cache_get(ilcf->index_cache, NULL,
                                            &r->uri, &crc);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http index cache get: " PTR_FMT, ctx->cache);

            if (ctx->cache && !ctx->cache->expired) {

                ctx->cache->accessed = ngx_cached_time;

                ctx->redirect.len = ctx->cache->data.value.len;
                ctx->redirect.data = ngx_palloc(r->pool, ctx->redirect.len + 1);
                if (ctx->redirect.data == NULL) {
                    ngx_http_cache_unlock(ilcf->index_cache, ctx->cache, log);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                ngx_memcpy(ctx->redirect.data, ctx->cache->data.value.data,
                           ctx->redirect.len + 1);
                ngx_http_cache_unlock(ilcf->index_cache, ctx->cache, log);

                return ngx_http_internal_redirect(r, &ctx->redirect, NULL);
            }
        }

#endif

#if 0
        ctx->path.data = ngx_palloc(r->pool, clcf->root.len + r->uri.len
                                             + ilcf->max_index_len
                                             - clcf->alias * clcf->name.len);
        if (ctx->path.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->redirect.data = ngx_cpymem(ctx->path.data, clcf->root.data,
                                        clcf->root.len);
#endif

        if (clcf->alias) {
            ctx->path.data = ngx_palloc(r->pool, clcf->root.len
                                              + r->uri.len + 1 - clcf->name.len
                                              + ilcf->max_index_len);
            if (ctx->path.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ctx->redirect.data = ngx_palloc(r->pool, r->uri.len
                                            + ilcf->max_index_len);
            if (ctx->redirect.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_memcpy(ctx->path.data, clcf->root.data, clcf->root.len);

            ctx->last = ngx_cpystrn(ctx->path.data + clcf->root.len,
                                    r->uri.data + clcf->name.len,
                                    r->uri.len + 1 - clcf->name.len);

#if 0
            /*
             * aliases usually have trailling "/",
             * set it in the start of the possible redirect
             */

            if (*ctx->redirect.data != '/') {
                ctx->redirect.data--; 
            }
#endif

        } else {
            ctx->path.data = ngx_palloc(r->pool, clcf->root.len + r->uri.len
                                                 + ilcf->max_index_len);
            if (ctx->path.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ctx->redirect.data = ngx_cpymem(ctx->path.data, clcf->root.data,
                                            clcf->root.len);

            ctx->last = ngx_cpystrn(ctx->redirect.data, r->uri.data,
                                    r->uri.len + 1);
        }
    }

    ctx->path.len = ctx->last - ctx->path.data;

    index = ilcf->indices.elts;
    for (/* void */; ctx->index < ilcf->indices.nelts; ctx->index++) {

        if (index[ctx->index].data[0] == '/') {
            name = index[ctx->index].data;

        } else {
            ngx_memcpy(ctx->last, index[ctx->index].data,
                       index[ctx->index].len + 1);
            name = ctx->path.data;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "open index \"%s\"", name);

        fd = ngx_open_file(name, NGX_FILE_RDONLY, NGX_FILE_OPEN);

        if (fd == (ngx_fd_t) NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (fd == NGX_INVALID_FILE) {
            err = ngx_errno;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, err,
                           ngx_open_file_n " %s failed", name);

            if (err == NGX_ENOTDIR) {
                return ngx_http_index_error(r, ctx, err);

            } else if (err == NGX_EACCES) {
                return ngx_http_index_error(r, ctx, err);
            }

            if (!ctx->tested) {
                rc = ngx_http_index_test_dir(r, ctx);

                if (rc != NGX_OK) {
                    return rc;
                }

                ctx->tested = 1;
            }

            if (err == NGX_ENOENT) {
                continue;
            }

            ngx_log_error(NGX_LOG_ERR, log, err,
                          ngx_open_file_n " %s failed", name);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }


        /* STUB: open file cache */

        r->file.name.data = name;
        r->file.fd = fd;

        if (index[ctx->index].data[0] == '/') {
            r->file.name.len = index[ctx->index].len;
            ctx->redirect.len = index[ctx->index].len;
            ctx->redirect.data = index[ctx->index].data;

        } else {
            if (clcf->alias) {
                name = ngx_cpymem(ctx->redirect.data, r->uri.data, r->uri.len);
                ngx_memcpy(name, index[ctx->index].data,
                           index[ctx->index].len + 1);
            }

            ctx->redirect.len = r->uri.len + index[ctx->index].len;
            r->file.name.len = clcf->root.len + r->uri.len
                                                - clcf->alias * clcf->name.len
                                                       + index[ctx->index].len;
        }

        /**/


#if (NGX_HTTP_CACHE)

        if (ilcf->index_cache) {

            if (ctx->cache) {
                if (ctx->redirect.len == ctx->cache->data.value.len
                    && ngx_memcmp(ctx->cache->data.value.data,
                                  ctx->redirect.data, ctx->redirect.len) == 0)
                {
                    ctx->cache->accessed = ngx_cached_time;
                    ctx->cache->updated = ngx_cached_time;
                    ngx_http_cache_unlock(ilcf->index_cache, ctx->cache, log);

                    return ngx_http_internal_redirect(r, &ctx->redirect, NULL);
                }
            }

            ctx->redirect.len++;
            ctx->cache = ngx_http_cache_alloc(ilcf->index_cache, ctx->cache,
                                              NULL, &r->uri, crc,
                                              &ctx->redirect, log);
            ctx->redirect.len--;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http index cache alloc: " PTR_FMT, ctx->cache);

            if (ctx->cache) {
                ctx->cache->fd = NGX_INVALID_FILE;
                ctx->cache->accessed = ngx_cached_time;
                ctx->cache->last_modified = 0;
                ctx->cache->updated = ngx_cached_time;
                ctx->cache->memory = 1;
                ngx_http_cache_unlock(ilcf->index_cache, ctx->cache, log);
            }
        }

#endif

        return ngx_http_internal_redirect(r, &ctx->redirect, NULL);
    }

    return NGX_DECLINED;
}


static ngx_int_t ngx_http_index_test_dir(ngx_http_request_t *r,
                                         ngx_http_index_ctx_t *ctx)
{
    ngx_err_t  err;

    ctx->path.data[ctx->path.len - 1] = '\0';
    ctx->path.data[ctx->path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http check dir: \"%s\"", ctx->path.data);

    if (ngx_file_info(ctx->path.data, &r->file.info) == -1) {

        err = ngx_errno;

        if (err == NGX_ENOENT) {
            ctx->path.data[ctx->path.len - 1] = '/';
            return ngx_http_index_error(r, ctx, err);
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                      ngx_file_info_n " %s failed", ctx->path.data);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->path.data[ctx->path.len - 1] = '/';

    if (ngx_is_dir(&r->file.info)) {
        return NGX_OK;
    }

    /* THINK: not reached ??? */
    return ngx_http_index_error(r, ctx, 0);
}


static ngx_int_t ngx_http_index_error(ngx_http_request_t *r,
                                      ngx_http_index_ctx_t *ctx, ngx_err_t err)
{
    if (err == NGX_EACCES) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "\"%s\" is forbidden", ctx->path.data);
    
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                  "\"%s\" is not found", ctx->path.data);
    return NGX_HTTP_NOT_FOUND;
}


static ngx_int_t ngx_http_index_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_push_array(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_index_handler;

    return NGX_OK;
}


static void *ngx_http_index_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_index_loc_conf_t  *conf;

    ngx_test_null(conf, ngx_palloc(cf->pool, sizeof(ngx_http_index_loc_conf_t)),
                  NGX_CONF_ERROR);

    ngx_init_array(conf->indices, cf->pool, 3, sizeof(ngx_str_t),
                   NGX_CONF_ERROR);
    conf->max_index_len = 0;

    conf->index_cache = NULL;

    return conf;
}


/* TODO: remove duplicate indices */

static char *ngx_http_index_merge_loc_conf(ngx_conf_t *cf,
                                           void *parent, void *child)
{
    ngx_http_index_loc_conf_t  *prev = parent;
    ngx_http_index_loc_conf_t  *conf = child;

    ngx_uint_t  i;
    ngx_str_t  *index, *prev_index;

    if (conf->max_index_len == 0) {
        if (prev->max_index_len != 0) {
            ngx_memcpy(conf, prev, sizeof(ngx_http_index_loc_conf_t));
            return NGX_CONF_OK;
        }

        ngx_test_null(index, ngx_push_array(&conf->indices), NGX_CONF_ERROR);
        index->len = sizeof(NGX_HTTP_DEFAULT_INDEX) - 1;
        index->data = (u_char *) NGX_HTTP_DEFAULT_INDEX;
        conf->max_index_len = sizeof(NGX_HTTP_DEFAULT_INDEX);

        return NGX_CONF_OK;
    }

    if (prev->max_index_len != 0) {

        prev_index = prev->indices.elts;
        for (i = 0; i < prev->indices.nelts; i++) {
            ngx_test_null(index, ngx_push_array(&conf->indices),
                          NGX_CONF_ERROR);
            index->len = prev_index[i].len;
            index->data = prev_index[i].data;
        }
    }

    if (conf->max_index_len < prev->max_index_len) {
        conf->max_index_len = prev->max_index_len;
    }

    if (conf->index_cache == NULL) {
        conf->index_cache = prev->index_cache;
    }

    return NGX_CONF_OK;
}


/* TODO: warn about duplicate indices */

static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf)
{
    ngx_http_index_loc_conf_t *ilcf = conf;

    ngx_uint_t  i;
    ngx_str_t  *index, *value;

    value = cf->args->elts;

    if (value[1].data[0] == '/' && ilcf->indices.nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "first index \"%s\" in \"%s\" directive "
                           "must not be absolute",
                           value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "index \"%s\" in \"%s\" directive is invalid",
                               value[1].data, cmd->name.data);
            return NGX_CONF_ERROR;
        }

        ngx_test_null(index, ngx_push_array(&ilcf->indices), NGX_CONF_ERROR);
        index->len = value[i].len;
        index->data = value[i].data;

        if (ilcf->max_index_len < index->len + 1) {
            ilcf->max_index_len = index->len + 1;
        }
    }

    return NGX_CONF_OK;
}
