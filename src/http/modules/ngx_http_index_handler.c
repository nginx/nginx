
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>
#include <ngx_http_index_handler.h>


static int ngx_http_index_test_dir(ngx_http_request_t *r);
static int ngx_http_index_init(ngx_pool_t *pool);
static void *ngx_http_index_create_conf(ngx_pool_t *pool);
static char *ngx_http_index_merge_conf(ngx_pool_t *p,
                                       void *parent, void *child);
static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                      char *conf);


static ngx_command_t ngx_http_index_commands[] = {

    {ngx_string("index"),
     NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_ANY,
     ngx_http_index_set_index,
     NGX_HTTP_LOC_CONF_OFFSET,
     0},

    {ngx_string(""), 0, NULL, 0, 0}
};


ngx_http_module_t  ngx_http_index_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* init server config */
    ngx_http_index_create_conf,            /* create location config */
    ngx_http_index_merge_conf,             /* merge location config */

    NULL,                                  /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    NULL,                                  /* output body filter */
    NULL,                                  /* next output body filter */

};


ngx_module_t  ngx_http_index_module = {
    0,                                     /* module index */
    &ngx_http_index_module_ctx,            /* module context */
    ngx_http_index_commands,               /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    ngx_http_index_init                    /* init module */
};


/*
   Try to open first index file before the test of the directory existence
   because the valid requests should be many more then invalid ones.
   If open() is failed then stat() should be more quickly because some data
   is already cached in the kernel.  Besides Win32 has ERROR_PATH_NOT_FOUND
   and Unix has ENOTDIR error (although it less helpfull).
*/

int ngx_http_index_handler(ngx_http_request_t *r)
{
    int          i, rc, test_dir;
    char        *name, *file;
    ngx_str_t    loc, *index;
    ngx_err_t    err;
    ngx_fd_t     fd;

    ngx_http_index_conf_t     *cf;
    ngx_http_core_loc_conf_t  *core_cf;

    cf = (ngx_http_index_conf_t *)
                        ngx_http_get_module_loc_conf(r, ngx_http_index_module);

    core_cf = (ngx_http_core_loc_conf_t *)
                         ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_test_null(r->path.data,
                  ngx_palloc(r->pool,
                             core_cf->doc_root.len + r->uri.len
                             + cf->max_index_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc.data = ngx_cpystrn(r->path.data, core_cf->doc_root.data,
                           core_cf->doc_root.len + 1);
    file = ngx_cpystrn(loc.data, r->uri.data, r->uri.len + 1);
    r->path.len = file - r->path.data;

    test_dir = 1;

    index = (ngx_str_t *) cf->indices->elts;
    for (i = 0; i < cf->indices->nelts; i++) {

        if (index[i].data[0] != '/') {
            ngx_memcpy(file, index[i].data, index[i].len + 1);
            name = r->path.data;

        } else {
            name = index[i].data;
        }

        fd = ngx_open_file(name, NGX_FILE_RDONLY);
        if (fd == NGX_INVALID_FILE) {
            err = ngx_errno;

ngx_log_error(NGX_LOG_DEBUG, r->connection->log, err,
              "DEBUG: " ngx_open_file_n " %s failed", name);

#if (WIN32)
            if (err == ERROR_PATH_NOT_FOUND) {
#else
            if (err == NGX_ENOTDIR) {
#endif
                r->path_not_found = 1;

            } else if (err == NGX_EACCES) {
                r->path_err = err;
                return NGX_HTTP_FORBIDDEN;
            }

            if (test_dir) {
                if (r->path_not_found) {
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
            loc.len = index[i].len;
            loc.data = index[i].data;

        } else {
            loc.len = r->uri.len + index[i].len;
            r->file.name.len = core_cf->doc_root.len + r->uri.len
                               + index[i].len;
        }

        return ngx_http_internal_redirect(r, loc);
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
                      "ngx_http_index_test_dir: "
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


static int ngx_http_index_init(ngx_pool_t *pool)
{
    ngx_http_handler_pt  *h;

    ngx_test_null(h, ngx_push_array(&ngx_http_index_handlers), NGX_ERROR);

    *h = ngx_http_index_handler;

    return NGX_OK;
}


static void *ngx_http_index_create_conf(ngx_pool_t *pool)
{
    ngx_http_index_conf_t  *conf;

    ngx_test_null(conf, ngx_pcalloc(pool, sizeof(ngx_http_index_conf_t)),
                  NGX_CONF_ERROR);

    ngx_test_null(conf->indices,
                  ngx_create_array(pool, 3, sizeof(ngx_str_t)),
                  NGX_CONF_ERROR);

    return conf;
}


/* STUB */
static char *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_index_conf_t *prev = (ngx_http_index_conf_t *) parent;
    ngx_http_index_conf_t *conf = (ngx_http_index_conf_t *) child;
    ngx_str_t  *index;

    if (conf->max_index_len == 0) {
        ngx_test_null(index, ngx_push_array(conf->indices), NGX_CONF_ERROR);
        index->len = sizeof(NGX_HTTP_INDEX) - 1;
        index->data = NGX_HTTP_INDEX;
        conf->max_index_len = sizeof(NGX_HTTP_INDEX);
    }

    /* FAIL: if first index is started with '/' */

    return NULL;
}


#if 0
static char *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_index_conf_t *prev = (ngx_http_index_conf_t *) parent;
    ngx_http_index_conf_t *conf = (ngx_http_index_conf_t *) child;
    ngx_str_t  *index;

    if (conf->max_index_len == 0) {
        if (prev->max_index_len != 0) {
            return prev;
        }

        ngx_test_null(index, ngx_push_array(conf->indices), NULL);
        index->len = sizeof(NGX_HTTP_INDEX) - 1;
        index->data = NGX_HTTP_INDEX;
        conf->max_index_len = sizeof(NGX_HTTP_INDEX);
    }

    return conf;
}
#endif

static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                      char *conf)
{
    ngx_http_index_conf_t *icf = (ngx_http_index_conf_t *) conf;
    int  i;
    ngx_str_t  *index, *value;

    value = (ngx_str_t *) cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        ngx_test_null(index, ngx_push_array(icf->indices), NGX_CONF_ERROR);
        index->len = value[i].len;
        index->data = value[i].data;

        if (icf->max_index_len < index->len) {
            icf->max_index_len = index->len;
        }
    }

    return NULL;
}
