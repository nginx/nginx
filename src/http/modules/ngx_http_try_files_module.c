
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t           *lengths;
    ngx_array_t           *values;
    ngx_str_t              name;

    unsigned               code:10;
    unsigned               test_dir:1;
} ngx_http_try_file_t;


typedef struct {
    ngx_http_try_file_t   *try_files;
} ngx_http_try_files_loc_conf_t;


static ngx_int_t ngx_http_try_files_handler(ngx_http_request_t *r);
static char *ngx_http_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_try_files_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_try_files_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_try_files_commands[] = {

    { ngx_string("try_files"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_try_files,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_try_files_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_try_files_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_try_files_create_loc_conf,    /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_try_files_module = {
    NGX_MODULE_V1,
    &ngx_http_try_files_module_ctx,        /* module context */
    ngx_http_try_files_commands,           /* module directives */
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
ngx_http_try_files_handler(ngx_http_request_t *r)
{
    size_t                          len, root, alias, reserve, allocated;
    u_char                         *p, *name;
    ngx_str_t                       path, args;
    ngx_uint_t                      test_dir;
    ngx_http_try_file_t            *tf;
    ngx_open_file_info_t            of;
    ngx_http_script_code_pt         code;
    ngx_http_script_engine_t        e;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_script_len_code_pt     lcode;
    ngx_http_try_files_loc_conf_t  *tlcf;

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_try_files_module);

    if (tlcf->try_files == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "try files handler");

    allocated = 0;
    root = 0;
    name = NULL;
    /* suppress MSVC warning */
    path.data = NULL;

    tf = tlcf->try_files;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    alias = clcf->alias;

    for ( ;; ) {

        if (tf->lengths) {
            ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

            e.ip = tf->lengths->elts;
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(ngx_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

        } else {
            len = tf->name.len;
        }

        if (!alias) {
            reserve = len > r->uri.len ? len - r->uri.len : 0;

        } else if (alias == NGX_MAX_SIZE_T_VALUE) {
            reserve = len;

        } else {
            reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
        }

        if (reserve > allocated || !allocated) {

            /* 16 bytes are preallocation */
            allocated = reserve + 16;

            if (ngx_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            name = path.data + root;
        }

        if (tf->values == NULL) {

            /* tf->name.len includes the terminating '\0' */

            ngx_memcpy(name, tf->name.data, tf->name.len);

            path.len = (name + tf->name.len - 1) - path.data;

        } else {
            e.ip = tf->values->elts;
            e.pos = name;
            e.flushed = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';

            if (alias && alias != NGX_MAX_SIZE_T_VALUE
                && ngx_strncmp(name, r->uri.data, alias) == 0)
            {
                ngx_memmove(name, name + alias, len - alias);
                path.len -= alias;
            }
        }

        test_dir = tf->test_dir;

        tf++;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trying to use %s: \"%s\" \"%s\"",
                       test_dir ? "dir" : "file", name, path.data);

        if (tf->lengths == NULL && tf->name.len == 0) {

            if (tf->code) {
                return tf->code;
            }

            path.len -= root;
            path.data += root;

            if (path.data[0] == '@') {
                (void) ngx_http_named_location(r, &path);

            } else {
                ngx_http_split_args(r, &path, &args);

                (void) ngx_http_internal_redirect(r, &path, &args);
            }

            ngx_http_finalize_request(r, NGX_DONE);
            return NGX_DONE;
        }

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            if (of.err == 0) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (of.err != NGX_ENOENT
                && of.err != NGX_ENOTDIR
                && of.err != NGX_ENAMETOOLONG)
            {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
                              "%s \"%s\" failed", of.failed, path.data);
            }

            continue;
        }

        if (of.is_dir != test_dir) {
            continue;
        }

        path.len -= root;
        path.data += root;

        if (!alias) {
            r->uri = path;

        } else if (alias == NGX_MAX_SIZE_T_VALUE) {
            if (!test_dir) {
                r->uri = path;
                r->add_uri_to_alias = 1;
            }

        } else {
            name = r->uri.data;

            r->uri.len = alias + path.len;
            r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
            if (r->uri.data == NULL) {
                r->uri.len = 0;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = ngx_copy(r->uri.data, name, alias);
            ngx_memcpy(p, path.data, path.len);
        }

        ngx_http_set_exten(r);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "try file uri: \"%V\"", &r->uri);

        return NGX_DECLINED;
    }

    /* not reached */
}


static char *
ngx_http_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_try_files_loc_conf_t *tlcf = conf;

    ngx_str_t                  *value;
    ngx_int_t                   code;
    ngx_uint_t                  i, n;
    ngx_http_try_file_t        *tf;
    ngx_http_script_compile_t   sc;

    if (tlcf->try_files) {
        return "is duplicate";
    }

    tf = ngx_pcalloc(cf->pool, cf->args->nelts * sizeof(ngx_http_try_file_t));
    if (tf == NULL) {
        return NGX_CONF_ERROR;
    }

    tlcf->try_files = tf;

    value = cf->args->elts;

    for (i = 0; i < cf->args->nelts - 1; i++) {

        tf[i].name = value[i + 1];

        if (tf[i].name.len > 0
            && tf[i].name.data[tf[i].name.len - 1] == '/'
            && i + 2 < cf->args->nelts)
        {
            tf[i].test_dir = 1;
            tf[i].name.len--;
            tf[i].name.data[tf[i].name.len] = '\0';
        }

        n = ngx_http_script_variables_count(&tf[i].name);

        if (n) {
            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

            sc.cf = cf;
            sc.source = &tf[i].name;
            sc.lengths = &tf[i].lengths;
            sc.values = &tf[i].values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;

            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

        } else {
            /* add trailing '\0' to length */
            tf[i].name.len++;
        }
    }

    if (tf[i - 1].name.data[0] == '=') {

        code = ngx_atoi(tf[i - 1].name.data + 1, tf[i - 1].name.len - 2);

        if (code == NGX_ERROR || code > 999) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid code \"%*s\"",
                               tf[i - 1].name.len - 1, tf[i - 1].name.data);
            return NGX_CONF_ERROR;
        }

        tf[i].code = code;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_try_files_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_try_files_loc_conf_t  *tlcf;

    tlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_try_files_loc_conf_t));
    if (tlcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     tlcf->try_files = NULL;
     */

    return tlcf;
}


static ngx_int_t
ngx_http_try_files_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_try_files_handler;

    return NGX_OK;
}
