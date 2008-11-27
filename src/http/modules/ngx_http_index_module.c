
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


#define NGX_HTTP_DEFAULT_INDEX   "index.html"


static ngx_int_t ngx_http_index_test_dir(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, u_char *path, u_char *last);
static ngx_int_t ngx_http_index_error(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, u_char *file, ngx_err_t err);

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
    u_char                       *p, *name;
    size_t                        len, nlen, root, allocated;
    ngx_int_t                     rc;
    ngx_str_t                     path, uri;
    ngx_log_t                    *log;
    ngx_uint_t                    i, dir_tested;
    ngx_http_index_t             *index;
    ngx_open_file_info_t          of;
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

    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_index_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    allocated = 0;
    root = 0;
    dir_tested = 0;
    name = NULL;
    path.data = NULL;

    index = ilcf->indices->elts;
    for (i = 0; i < ilcf->indices->nelts; i++) {

        if (index[i].lengths == NULL) {

            if (index[i].name.data[0] == '/') {
                return ngx_http_internal_redirect(r, &index[i].name, &r->args);
            }

            len = ilcf->max_index_len;
            nlen = index[i].name.len;

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

            nlen = len;

            /* 16 bytes are preallocation */

            len += 16;
        }

        if (len > (size_t) (path.data + allocated - name)) {

            name = ngx_http_map_uri_to_path(r, &path, &root, len);
            if (name == NULL) {
                return NGX_ERROR;
            }

            allocated = path.len;
        }

        if (index[i].values == NULL) {

            /* index[i].name.len includes the terminating '\0' */

            ngx_memcpy(name, index[i].name.data, index[i].name.len);

            path.len = (name + index[i].name.len - 1) - path.data;

        } else {
            e.ip = index[i].values->elts;
            e.pos = name;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }

            if (*name == '/') {
                uri.len = nlen - 1;
                uri.data = name;
                return ngx_http_internal_redirect(r, &uri, &r->args);
            }

            path.len = e.pos - path.data;

            *e.pos++ = '\0';
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "open index \"%V\"", &path);

        of.test_dir = 0;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, of.err,
                           ngx_open_file_n " \"%s\" failed", path.data);

            if (of.err == 0) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (of.err == NGX_ENOTDIR || of.err == NGX_EACCES) {
                return ngx_http_index_error(r, clcf, path.data, of.err);
            }

            if (!dir_tested) {
                rc = ngx_http_index_test_dir(r, clcf, path.data, name - 1);

                if (rc != NGX_OK) {
                    return rc;
                }

                dir_tested = 1;
            }

            if (of.err == NGX_ENOENT) {
                continue;
            }

            ngx_log_error(NGX_LOG_ERR, log, of.err,
                          ngx_open_file_n " \"%s\" failed", path.data);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        uri.len = r->uri.len + nlen - 1;

        if (!clcf->alias) {
            uri.data = path.data + root;

        } else {
            uri.data = ngx_palloc(r->pool, uri.len);
            if (uri.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = ngx_copy(uri.data, r->uri.data, r->uri.len);
            ngx_memcpy(p, name, nlen - 1);
        }

        return ngx_http_internal_redirect(r, &uri, &r->args);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_index_test_dir(ngx_http_request_t *r, ngx_http_core_loc_conf_t *clcf,
    u_char *path, u_char *last)
{
    u_char                c;
    ngx_str_t             dir;
    ngx_open_file_info_t  of;

    c = *last;
    if (c != '/' || path == last) {
        /* "alias" without trailing slash */
        c = *(++last);
    }
    *last = '\0';

    dir.len = last - path;
    dir.data = path;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http index check dir: \"%V\"", &dir);

    of.test_dir = 1;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = 0;
    of.errors = clcf->open_file_cache_errors;

    if (ngx_open_cached_file(clcf->open_file_cache, &dir, &of, r->pool)
        != NGX_OK)
    {
        if (of.err) {

            if (of.err == NGX_ENOENT) {
                *last = c;
                return ngx_http_index_error(r, clcf, dir.data, NGX_ENOENT);
            }

            if (of.err == NGX_EACCES) {

                *last = c;

                /*
                 * ngx_http_index_test_dir() is called after the first index
                 * file testing has returned an error distinct from NGX_EACCES.
                 * This means that directory searching is allowed.
                 */

                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
                          ngx_open_file_n " \"%s\" failed", dir.data);
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *last = c;

    if (of.is_dir) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "\"%s\" is not a directory", dir.data);

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_http_index_error(ngx_http_request_t *r, ngx_http_core_loc_conf_t  *clcf,
    u_char *file, ngx_err_t err)
{
    if (err == NGX_EACCES) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "\"%s\" is forbidden", file);

        return NGX_HTTP_FORBIDDEN;
    }

    if (clcf->log_not_found) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "\"%s\" is not found", file);
    }

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
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "only the last index in \"index\" directive "
                               "should be absolute");
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

            if (index->name.data[0] == '/') {
                continue;
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
