
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


static void *ngx_http_index_create_conf(ngx_pool_t *pool);
static char *ngx_http_index_merge_conf(ngx_pool_t *p,
                                       void *parent, void *child);
static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
                                      char *conf);


static ngx_command_t ngx_http_index_commands[] = {

    {ngx_string("index"),
     NGX_CONF_ANY,
     ngx_http_index_set_index,
     NGX_HTTP_LOC_CONF,
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
    NULL                                   /* init module */
};


int ngx_http_index_handler(ngx_http_request_t *r)
{
    int          i;
    char        *name, *file;
    ngx_str_t    loc, *index;
    ngx_err_t    err;
    ngx_fd_t     fd;

    ngx_http_index_conf_t     *cf;
    ngx_http_core_loc_conf_t  *core_cf;

    cf = (ngx_http_index_conf_t *)
                   ngx_http_get_module_loc_conf(r, ngx_http_index_module_ctx);

    core_cf = (ngx_http_core_loc_conf_t *)
                    ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    ngx_test_null(name,
                  ngx_palloc(r->pool,
                             core_cf->doc_root.len + r->uri.len
                             + cf->max_index_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc.data = ngx_cpystrn(name, core_cf->doc_root.data,
                           core_cf->doc_root.len + 1);
    file = ngx_cpystrn(loc.data, r->uri.data, r->uri.len + 1);

    index = (ngx_str_t *) cf->indices->elts;
    for (i = 0; i < cf->indices->nelts; i++) {
        ngx_memcpy(file, index[i].data, index[i].len + 1);

        fd = ngx_open_file(name, NGX_FILE_RDONLY);
        if (fd == NGX_INVALID_FILE) {
            err = ngx_errno;
            if (err == NGX_ENOENT) {
                continue;
            }
#if (WIN32)
            if (err == ERROR_PATH_NOT_FOUND) {
                continue;
            }
#endif

            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          ngx_open_file_n " %s failed", name);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.name.len = core_cf->doc_root.len + r->uri.len + index[i].len;
        r->file.name.data = name; 
        r->file.fd = fd; 

        loc.len = r->uri.len + index[i].len;
        return ngx_http_internal_redirect(r, loc);
    }

    return NGX_DECLINED;
}


static void *ngx_http_index_create_conf(ngx_pool_t *pool)
{
    ngx_http_index_conf_t  *conf;

    ngx_test_null(conf, ngx_pcalloc(pool, sizeof(ngx_http_index_conf_t)),
                  NGX_CONF_ERROR);

    ngx_test_null(conf->indices,
                  ngx_create_array(pool, sizeof(ngx_str_t), 3),
                  NGX_CONF_ERROR);

    return conf;
}


static char *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_index_conf_t *prev = (ngx_http_index_conf_t *) parent;
    ngx_http_index_conf_t *conf = (ngx_http_index_conf_t *) child;
    ngx_str_t  *index;

    ngx_test_null(index, ngx_push_array(conf->indices), NGX_CONF_ERROR);
    index->len = sizeof(NGX_HTTP_INDEX) - 1;
    index->data = NGX_HTTP_INDEX;
    conf->max_index_len = sizeof(NGX_HTTP_INDEX);

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
        ngx_test_null(index, ngx_push_array(icf->indices), NULL);
        index->len = value[i].len;
        index->data = value[i].data;

        if (icf->max_index_len < index->len) {
            icf->max_index_len = index->len;
        }
    }

    return NULL;
}
