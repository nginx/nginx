
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t  enable;
} ngx_http_random_index_loc_conf_t;


#define NGX_HTTP_RANDOM_INDEX_PREALLOCATE  50


static ngx_int_t ngx_http_random_index_error(ngx_http_request_t *r,
    ngx_dir_t *dir, ngx_str_t *name);
static ngx_int_t ngx_http_random_index_init(ngx_conf_t *cf);
static void *ngx_http_random_index_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_random_index_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_random_index_commands[] = {

    { ngx_string("random_index"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_random_index_loc_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_random_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_random_index_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_random_index_create_loc_conf, /* create location configration */
    ngx_http_random_index_merge_loc_conf   /* merge location configration */
};


ngx_module_t  ngx_http_random_index_module = {
    NGX_MODULE_V1,
    &ngx_http_random_index_module_ctx,     /* module context */
    ngx_http_random_index_commands,        /* module directives */
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
ngx_http_random_index_handler(ngx_http_request_t *r)
{
    u_char                            *last, *filename;
    size_t                             len, allocated, root;
    ngx_err_t                          err;
    ngx_int_t                          rc;
    ngx_str_t                          path, uri, *name;
    ngx_dir_t                          dir;
    ngx_uint_t                         n, level;
    ngx_array_t                        names;
    ngx_http_random_index_loc_conf_t  *rlcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_DECLINED;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_random_index_module);

    if (!rlcf->enable) {
        return NGX_DECLINED;
    }

#if (NGX_HAVE_D_TYPE)
    len = NGX_DIR_MASK_LEN;
#else
    len = NGX_HTTP_RANDOM_INDEX_PREALLOCATE;
#endif

    last = ngx_http_map_uri_to_path(r, &path, &root, len);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;

    path.len = last - path.data - 1;
    path.data[path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http random index: \"%s\"", path.data);

    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        err = ngx_errno;

        if (err == NGX_ENOENT
            || err == NGX_ENOTDIR
            || err == NGX_ENAMETOOLONG)
        {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

    if (ngx_array_init(&names, r->pool, 32, sizeof(ngx_str_t)) != NGX_OK) {
        return ngx_http_random_index_error(r, &dir, &path);
    }

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                              ngx_read_dir_n " \"%V\" failed", &path);
                return ngx_http_random_index_error(r, &dir, &path);
            }

            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http random index file: \"%s\"", ngx_de_name(&dir));

        if (ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        len = ngx_de_namelen(&dir);

        if (dir.type == 0 || ngx_de_is_link(&dir)) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + NGX_HTTP_RANDOM_INDEX_PREALLOCATE;

                filename = ngx_pnalloc(r->pool, allocated);
                if (filename == NULL) {
                    return ngx_http_random_index_error(r, &dir, &path);
                }

                last = ngx_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            ngx_cpystrn(last, ngx_de_name(&dir), len + 1);

            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOENT) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                  ngx_de_info_n " \"%s\" failed", filename);
                    return ngx_http_random_index_error(r, &dir, &path);
                }

                if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                                  ngx_de_link_info_n " \"%s\" failed",
                                  filename);
                    return ngx_http_random_index_error(r, &dir, &path);
                }
            }
        }

        if (!ngx_de_is_file(&dir)) {
            continue;
        }

        name = ngx_array_push(&names);
        if (name == NULL) {
            return ngx_http_random_index_error(r, &dir, &path);
        }

        name->len = len;

        name->data = ngx_pnalloc(r->pool, len);
        if (name->data == NULL) {
            return ngx_http_random_index_error(r, &dir, &path);
        }

        ngx_memcpy(name->data, ngx_de_name(&dir), len);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", &path);
    }

    n = names.nelts;

    if (n == 0) {
        return NGX_DECLINED;
    }

    name = names.elts;

    n = (ngx_uint_t) (((uint64_t) ngx_random() * n) / 0x80000000);

    uri.len = r->uri.len + name[n].len;

    uri.data = ngx_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_copy(uri.data, r->uri.data, r->uri.len);
    ngx_memcpy(last, name[n].data, name[n].len);

    return ngx_http_internal_redirect(r, &uri, &r->args);
}


static ngx_int_t
ngx_http_random_index_error(ngx_http_request_t *r, ngx_dir_t *dir,
    ngx_str_t *name)
{
    if (ngx_close_dir(dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", name);
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
ngx_http_random_index_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_random_index_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_random_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_random_index_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_random_index_loc_conf_t *prev = parent;
    ngx_http_random_index_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_random_index_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_random_index_handler;

    return NGX_OK;
}
