
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t  indices;
    size_t       max_index_len;
} ngx_http_index_conf_t;


#define NGX_HTTP_DEFAULT_INDEX   "index.html"


static int ngx_http_index_test_dir(ngx_http_request_t *r);
static int ngx_http_index_init(ngx_cycle_t *cycle);
static void *ngx_http_index_create_conf(ngx_pool_t *pool);
static char *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent,
                                                                  void *child);
static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                                                   void *conf);


static ngx_command_t ngx_http_index_commands[] = {

    {ngx_string("index"),
     NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
     ngx_http_index_set_index,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_index_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_index_create_conf,            /* create location configration */
    ngx_http_index_merge_conf              /* merge location configration */
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
   Try to open the first index file before the directory existence test
   because the valid requests should be many more than invalid ones.
   If open() failed then stat() should be more quickly because some data
   is already cached in the kernel.
   Besides Win32 has ERROR_PATH_NOT_FOUND (NGX_ENOTDIR).
   Unix has ENOTDIR error, although it less helpfull - it shows only
   that path contains the usual file in place of the directory.
*/

int ngx_http_index_handler(ngx_http_request_t *r)
{
    int                        i, rc, test_dir, path_not_found;
    char                      *name, *file;
    ngx_str_t                  redirect, *index;
    ngx_err_t                  err;
    ngx_fd_t                   fd;
    ngx_http_index_conf_t     *icf;
    ngx_http_core_loc_conf_t  *clcf;

    icf = ngx_http_get_module_loc_conf(r, ngx_http_index_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_test_null(r->path.data,
                  ngx_palloc(r->pool,
                             clcf->doc_root.len + r->uri.len
                             + icf->max_index_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    redirect.data = ngx_cpymem(r->path.data, clcf->doc_root.data,
                               clcf->doc_root.len);
    file = ngx_cpystrn(redirect.data, r->uri.data, r->uri.len + 1);
    r->path.len = file - r->path.data;

    test_dir = 1;
    path_not_found = 1;

    index = icf->indices.elts;
    for (i = 0; i < icf->indices.nelts; i++) {

        if (index[i].data[0] != '/') {
            ngx_memcpy(file, index[i].data, index[i].len + 1);
            name = r->path.data;

        } else {
            name = index[i].data;
        }

        fd = ngx_open_file(name, NGX_FILE_RDONLY, NGX_FILE_OPEN);
        if (fd == NGX_INVALID_FILE) {
            err = ngx_errno;

ngx_log_error(NGX_LOG_DEBUG, r->connection->log, err,
              "DEBUG: " ngx_open_file_n " %s failed", name);

            if (err == NGX_ENOTDIR) {
                path_not_found = 1;

            } else if (err == NGX_EACCES) {
                r->path_err = err;
                return NGX_HTTP_FORBIDDEN;
            }

            if (test_dir) {
                if (path_not_found) {
                    r->path_err = err;
                    return NGX_HTTP_NOT_FOUND;
                }

                rc = ngx_http_index_test_dir(r);
                if (rc != NGX_OK) {
                    return rc;
                }

                test_dir = 0;
            }

            if (err == NGX_ENOENT) {
                continue;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          ngx_open_file_n " %s failed", name);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.name.data = name;
        r->file.fd = fd;

        if (index[i].data[0] == '/') {
            r->file.name.len = index[i].len;
            redirect.len = index[i].len;
            redirect.data = index[i].data;

        } else {
            redirect.len = r->uri.len + index[i].len;
            r->file.name.len = clcf->doc_root.len + r->uri.len + index[i].len;
        }

        return ngx_http_internal_redirect(r, &redirect, NULL);
    }

    return NGX_DECLINED;
}


static int ngx_http_index_test_dir(ngx_http_request_t *r)
{
    r->path.data[r->path.len - 1] = '\0';
    r->path.data[r->path.len] = '\0';

ngx_log_debug(r->connection->log, "IS_DIR: %s" _ r->path.data);

#if 0
    if (r->path_err == NGX_EACCES) {
        return NGX_HTTP_FORBIDDEN;
    }
#endif

    if (ngx_file_type(r->path.data, &r->file.info) == -1) {

        r->path_err = ngx_errno;

        if (r->path_err == NGX_ENOENT) {
            r->path.data[r->path.len - 1] = '/';
            return NGX_HTTP_NOT_FOUND;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, r->path_err,
                      ngx_file_type_n " %s failed", r->path.data);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->path.data[r->path.len - 1] = '/';

    if (ngx_is_dir(r->file.info)) {
        return NGX_OK;

    } else {
        return NGX_HTTP_NOT_FOUND;
    }
}


static int ngx_http_index_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_conf_ctx_t        *ctx;
    ngx_http_core_main_conf_t  *cmcf;

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];

    ngx_test_null(h, ngx_push_array(&cmcf->index_handlers), NGX_ERROR);

    *h = ngx_http_index_handler;

    return NGX_OK;
}


static void *ngx_http_index_create_conf(ngx_pool_t *pool)
{
    ngx_http_index_conf_t  *conf;

    ngx_test_null(conf, ngx_palloc(pool, sizeof(ngx_http_index_conf_t)),
                  NGX_CONF_ERROR);

    ngx_init_array(conf->indices, pool, 3, sizeof(ngx_str_t), NGX_CONF_ERROR);
    conf->max_index_len = 0;

    return conf;
}


/* TODO: remove duplicate indices */

static char *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_index_conf_t *prev = parent;
    ngx_http_index_conf_t *conf = child;

    int         i;
    ngx_str_t  *index, *prev_index;

    if (conf->max_index_len == 0) {
        if (prev->max_index_len != 0) {
            ngx_memcpy(conf, prev, sizeof(ngx_http_index_conf_t));
            return NGX_CONF_OK;
        }

        ngx_test_null(index, ngx_push_array(&conf->indices), NGX_CONF_ERROR);
        index->len = sizeof(NGX_HTTP_DEFAULT_INDEX) - 1;
        index->data = NGX_HTTP_DEFAULT_INDEX;
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

    return NGX_CONF_OK;
}


/* TODO: warn about duplicate indices */

static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf)
{
    ngx_http_index_conf_t *icf = conf;

    int         i;
    ngx_str_t  *index, *value;

    value = cf->args->elts;

    if (value[1].data[0] == '/' && icf->indices.nelts == 0) {
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

        ngx_test_null(index, ngx_push_array(&icf->indices), NGX_CONF_ERROR);
        index->len = value[i].len;
        index->data = value[i].data;

        if (icf->max_index_len < index->len + 1) {
            icf->max_index_len = index->len + 1;
        }
    }

    return NGX_CONF_OK;
}
