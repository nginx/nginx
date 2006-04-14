
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DAV_OFF   2

typedef struct {
    ngx_uint_t  methods;
} ngx_http_dav_loc_conf_t;


static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_handler(ngx_http_request_t *r);
static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_dav_init(ngx_cycle_t *cycle);


static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
    { ngx_string("off"), NGX_HTTP_DAV_OFF },
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_dav_commands[] = {

    { ngx_string("dav_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, methods),
      &ngx_http_dav_methods_mask },

      ngx_null_command
};


ngx_http_module_t  ngx_http_dav_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dav_create_loc_conf,          /* create location configuration */
    ngx_http_dav_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_dav_module = {
    NGX_MODULE_V1,
    &ngx_http_dav_module_ctx,              /* module context */
    ngx_http_dav_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_dav_init,                     /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_dav_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                 path;
    ngx_http_dav_loc_conf_t  *dlcf;

    /* TODO: Win32 */
    if (r->zero_in_uri) {
        return NGX_DECLINED;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (!(r->method & dlcf->methods)) {
        return NGX_DECLINED;
    }

    switch (r->method) {

    case NGX_HTTP_PUT:

        if (r->uri.data[r->uri.len - 1] == '/') {
            return NGX_DECLINED;
        }

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_delete_incomplete_file = 1;
        r->request_body_file_group_access = 1;

        rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_DELETE:

        if (r->uri.data[r->uri.len - 1] == '/') {
            return NGX_DECLINED;
        }

        ngx_http_map_uri_to_path(r, &path, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http delete filename: \"%s\"", path.data);

        if (ngx_delete_file(path.data) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed", path.data);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_HTTP_NO_CONTENT;
    }

    return NGX_DECLINED;
}


static void
ngx_http_dav_put_handler(ngx_http_request_t *r)
{
    u_char                    *location;
    ngx_err_t                  err;
    ngx_str_t                 *temp, path;
    ngx_uint_t                 status;
    ngx_file_info_t            fi;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_http_map_uri_to_path(r, &path, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (ngx_file_info(path.data, &fi) == -1) {
        status = NGX_HTTP_CREATED;

    } else {
        status = NGX_HTTP_NO_CONTENT;
    }

    if (ngx_rename_file(temp->data, path.data) != NGX_FILE_ERROR) {
        goto ok;
    }

    err = ngx_errno;

#if (NGX_WIN32)

    if (err == NGX_EEXIST) {
        if (ngx_win32_rename_file(temp, &path, r->pool) != NGX_ERROR) {

            if (ngx_rename_file(temp->data, path.data) != NGX_FILE_ERROR) {
                goto ok;
            }
        }

        err = ngx_errno;
    }

#endif

    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                  ngx_rename_file_n " \"%s\" failed", path.data);

    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;

ok:

    if (status == NGX_HTTP_CREATED) {

        r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
        if (r->headers_out.location == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (!clcf->alias && clcf->root_lengths == NULL) {
            location = path.data + clcf->root.len;

        } else {
            location = ngx_palloc(r->pool, r->uri.len);
            if (location == NULL) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_memcpy(location, r->uri.data, r->uri.len);
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        r->headers_out.location->value.len = r->uri.len;
        r->headers_out.location->value.data = location;

    }

    r->headers_out.status = status;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));
    return;
}


static void *
ngx_http_dav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dav_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->methods = 0;
     */

    return conf;
}


static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t  *prev = parent;
    ngx_http_dav_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                              (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_OFF));

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dav_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_handler;

    return NGX_OK;
}
