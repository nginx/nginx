
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_config_command.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_index_handler.h>


static void *ngx_http_index_create_conf(ngx_pool_t *pool);
static char *ngx_http_index_set_index(ngx_pool_t *p, void *conf, char *value);

static ngx_command_t ngx_http_index_commands[];


ngx_http_module_t  ngx_http_index_module = {
    NGX_HTTP_MODULE,
    NULL,                                  /* create server config */
    ngx_http_index_create_conf,            /* create location config */
    ngx_http_index_commands,               /* module directives */
    NULL,                                  /* init module */
    NULL,                                  /* init output body filter */
};


static ngx_command_t ngx_http_index_commands[] = {

    {"index", ngx_http_index_set_index, NULL,
     NGX_HTTP_LOC_CONF, NGX_CONF_ITERATE,
     "set index files"},

    {NULL}

};

int ngx_http_index_handler(ngx_http_request_t *r)
{
    int          index_len, i;
    char        *name, *loc, *file;
    ngx_err_t    err;
    ngx_fd_t     fd;

    ngx_http_index_file_t  *index;
    ngx_http_index_conf_t  *cf;

    cf = (ngx_http_index_conf_t *)
                            ngx_get_module_loc_conf(r, ngx_http_index_module);

    index_len = (*(r->uri_end - 1) == '/') ? cf->max_index_len : 0;

    ngx_test_null(name,
                  ngx_palloc(r->pool, r->uri_end - r->uri_start + index_len
                                      + r->server->doc_root_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc = ngx_cpystrn(name, r->server->doc_root, r->server->doc_root_len);
    file = ngx_cpystrn(loc, r->uri_start, r->uri_end - r->uri_start + 1);

    index = (ngx_http_index_file_t *) cf->indices->elts;
    for (i = 0; i < cf->indices->nelts; i++) {
        ngx_memcpy(file, index[i].name, index[i].len);

        fd = ngx_open_file(name, NGX_FILE_RDONLY);
        if (fd == -1) {
            err = ngx_errno;
            if (err == NGX_ENOENT)
                continue;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          ngx_open_file_n " %s failed", name);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->filename = name; 
        r->fd = fd; 

        return ngx_http_internal_redirect(r, loc);
    }

    return NGX_DECLINED;
}

static void *ngx_http_index_create_conf(ngx_pool_t *pool)
{
    ngx_http_index_conf_t  *conf;

    ngx_test_null(conf, ngx_pcalloc(pool, sizeof(ngx_http_index_conf_t)), NULL);

    ngx_test_null(conf->indices,
                  ngx_create_array(pool, sizeof(ngx_http_index_file_t), 3),
                  NULL);

    return conf;
}

static void *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_index_conf_t *prev = (ngx_http_index_conf_t *) parent;
    ngx_http_index_conf_t *conf = (ngx_http_index_conf_t *) child;
    ngx_http_index_file_t *index;

    if (conf->max_index_len == 0) {
        if (prev->max_index_len != 0)
            return prev;

        ngx_test_null(index, ngx_push_array(conf->indices), NULL);
        index->name = NGX_HTTP_INDEX;
        conf->max_index_len = index->len = sizeof(NGX_HTTP_INDEX);
    }

    return conf;
}

static char *ngx_http_index_set_index(ngx_pool_t *p, void *conf, char *value)
{
    ngx_http_index_conf_t *cf = (ngx_http_index_conf_t *) conf;
    ngx_http_index_file_t *index;

    ngx_test_null(index, ngx_push_array(cf->indices), NULL);
    index->name = value;
    index->len = strlen(value);

    if (cf->max_index_len < index->len)
        cf->max_index_len = index->len;

    return NULL;
}
