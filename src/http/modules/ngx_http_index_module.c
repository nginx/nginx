
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                name;
    ngx_array_t             *lengths;
    ngx_array_t             *values;
} ngx_http_index_t;


typedef struct {
    ngx_array_t             *indices;    /* array of ngx_http_index_t */
    size_t                   max_index_len;
} ngx_http_index_loc_conf_t;


typedef struct {
    ngx_uint_t               current;

    ngx_str_t                path;
    ngx_str_t                index;

    size_t                   root;

    ngx_uint_t               tested;     /* unsigned  tested:1 */
} ngx_http_index_ctx_t;


#define NGX_HTTP_DEFAULT_INDEX   "index.html"


static ngx_int_t ngx_http_index_test_dir(ngx_http_request_t *r,
    ngx_http_index_ctx_t *ctx);
static ngx_int_t ngx_http_index_error(ngx_http_request_t *r,
    ngx_http_index_ctx_t *ctx, ngx_err_t err);

static ngx_int_t ngx_http_index_init(ngx_conf_t *cf);
static void *ngx_http_index_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_index_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_index_commands[] = {

    { ngx_string("index"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
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


static ngx_http_module_t  ngx_http_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_index_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_index_create_loc_conf,        /* create location configration */
    ngx_http_index_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_index_module = {
    NGX_MODULE_V1,
    &ngx_http_index_module_ctx,            /* module context */
    ngx_http_index_commands,               /* module directives */
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


/*
 * Try to open the first index file before the test of the directory existence
 * because the valid requests should be many more than invalid ones.
 * If open() would fail, then stat() should be more quickly because some data
 * is already cached in the kernel.
 * Besides, Win32 has ERROR_PATH_NOT_FOUND (NGX_ENOTDIR).
 * Unix has ENOTDIR error, although it less helpfull - it points only
 * that path contains the usual file in place of the directory.
 */

static ngx_int_t
ngx_http_index_handler(ngx_http_request_t *r)
{
    u_char                       *last;
    size_t                        len;
    ngx_fd_t                      fd;
    ngx_int_t                     rc;
    ngx_err_t                     err;
    ngx_str_t                     uri;
    ngx_log_t                    *log;
    ngx_uint_t                    i;
    ngx_http_index_t             *index;
    ngx_http_index_ctx_t         *ctx;
    ngx_pool_cleanup_t           *cln;
    ngx_pool_cleanup_file_t      *clnf;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_index_loc_conf_t    *ilcf;
    ngx_http_script_len_code_pt   lcode;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_DECLINED;
    }

    /* TODO: Win32 */
    if (r->zero_in_uri) {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    /*
     * we use context because the handler supports an async file opening,
     * and may be called several times
     */

    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_index_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_index_module);
    if (ctx == NULL) {

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_index_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_index_module);
    }

    index = ilcf->indices->elts;
    for (i = ctx->current; i < ilcf->indices->nelts; i++) {

        if (index[i].lengths == NULL) {

            if (index[i].name.data[0] == '/') {
                return ngx_http_internal_redirect(r, &index[i].name, &r->args);
            }

            len = ilcf->max_index_len;
            ctx->index.len = index[i].name.len;

        } else {
            ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

            e.ip = index[i].lengths->elts;
            e.request = r;
            e.flushed = 1;

            /* 1 byte for terminating '\0' */

            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(ngx_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

            ctx->index.len = len;

            /* 16 bytes are preallocation */

            len += 16;
        }

        if (len > (size_t) (ctx->path.data + ctx->path.len - ctx->index.data)) {

            last = ngx_http_map_uri_to_path(r, &ctx->path, &ctx->root, len);
            if (last == NULL) {
                return NGX_ERROR;
            }

            ctx->index.data = last;
        }

        if (index[i].values == NULL) {

            /* index[i].name.len includes the terminating '\0' */

            ngx_memcpy(ctx->index.data, index[i].name.data, index[i].name.len);

        } else {
            e.ip = index[i].values->elts;
            e.pos = ctx->index.data;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }

            if (*ctx->index.data == '/') {
                ctx->index.len--;
                return ngx_http_internal_redirect(r, &ctx->index, &r->args);
            }

            *e.pos++ = '\0';
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "open index \"%s\"", ctx->path.data);

        cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        fd = ngx_open_file(ctx->path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

        if (fd == (ngx_fd_t) NGX_AGAIN) {
            ctx->current = i;
            return NGX_AGAIN;
        }

        if (fd == NGX_INVALID_FILE) {
            err = ngx_errno;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, err,
                           ngx_open_file_n " \"%s\" failed", ctx->path.data);

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
                          ngx_open_file_n " \"%s\" failed", ctx->path.data);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_pool_cleanup_file;
        clnf = cln->data;

        clnf->fd = fd;
        clnf->name = ctx->path.data;
        clnf->log = r->pool->log;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        uri.len = r->uri.len + ctx->index.len - 1;

        if (!clcf->alias) {
            uri.data = ctx->path.data + ctx->root;

        } else {
            uri.data = ngx_palloc(r->pool, uri.len);
            if (uri.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(uri.data, r->uri.data, r->uri.len);
            ngx_memcpy(last, ctx->index.data, ctx->index.len - 1);
        }

        return ngx_http_internal_redirect(r, &uri, &r->args);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_index_test_dir(ngx_http_request_t *r, ngx_http_index_ctx_t *ctx)
{
    u_char           c;
    ngx_uint_t       i;
    ngx_err_t        err;
    ngx_file_info_t  fi;

    c = *(ctx->index.data - 1);
    i = (c == '/') ? 1 : 0;
    *(ctx->index.data - i) = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http index check dir: \"%s\"", ctx->path.data);

    if (ngx_file_info(ctx->path.data, &fi) == -1) {

        err = ngx_errno;

        if (err == NGX_ENOENT) {
            *(ctx->index.data - i) = c;
            return ngx_http_index_error(r, ctx, err);
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                      ngx_file_info_n " \"%s\" failed", ctx->path.data);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *(ctx->index.data - i) = c;

    if (ngx_is_dir(&fi)) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "\"%s\" is not a directory", ctx->path.data);

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_http_index_error(ngx_http_request_t *r, ngx_http_index_ctx_t *ctx,
    ngx_err_t err)
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


static void *
ngx_http_index_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_index_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_index_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->indices = NULL;
    conf->max_index_len = 0;

    return conf;
}


static char *
ngx_http_index_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_index_loc_conf_t  *prev = parent;
    ngx_http_index_loc_conf_t  *conf = child;

    ngx_http_index_t  *index;

    if (conf->indices == NULL) {
        conf->indices = prev->indices;
        conf->max_index_len = prev->max_index_len;
    }

    if (conf->indices == NULL) {
        conf->indices = ngx_array_create(cf->pool, 1, sizeof(ngx_http_index_t));
        if (conf->indices == NULL) {
            return NGX_CONF_ERROR;
        }

        index = ngx_array_push(conf->indices);
        if (index == NULL) {
            return NGX_CONF_ERROR;
        }

        index->name.len = sizeof(NGX_HTTP_DEFAULT_INDEX);
        index->name.data = (u_char *) NGX_HTTP_DEFAULT_INDEX;
        index->lengths = NULL;
        index->values = NULL;

        conf->max_index_len = sizeof(NGX_HTTP_DEFAULT_INDEX);

        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_index_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_index_handler;

    return NGX_OK;
}


/* TODO: warn about duplicate indices */

static char *
ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_index_loc_conf_t *ilcf = conf;

    ngx_str_t                  *value;
    ngx_uint_t                  i, n;
    ngx_http_index_t           *index;
    ngx_http_script_compile_t   sc;

    if (ilcf->indices == NULL) {
        ilcf->indices = ngx_array_create(cf->pool, 2, sizeof(ngx_http_index_t));
        if (ilcf->indices == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].data[0] == '/' && i != cf->args->nelts - 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "only the last index in \"index\" directive "
                               "may be absolute");
            return NGX_CONF_ERROR;
        }

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "index \"%V\" in \"index\" directive is invalid",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        index = ngx_array_push(ilcf->indices);
        if (index == NULL) {
            return NGX_CONF_ERROR;
        }

        index->name.len = value[i].len;
        index->name.data = value[i].data;
        index->lengths = NULL;
        index->values = NULL;

        n = ngx_http_script_variables_count(&value[i]);

        if (n == 0) {
            if (ilcf->max_index_len < index->name.len) {
                ilcf->max_index_len = index->name.len;
            }

            /* include the terminating '\0' to the length to use ngx_copy() */
            index->name.len++;

            continue;
        }

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[i];
        sc.lengths = &index->lengths;
        sc.values = &index->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
