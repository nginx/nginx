
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DAV_OFF   2

typedef struct {
    ngx_uint_t  methods;
    ngx_flag_t  create_full_put_path;
    ngx_uint_t  access;
} ngx_http_dav_loc_conf_t;


static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_error(ngx_http_request_t *, ngx_err_t err,
    ngx_int_t not_found, char *failed, u_char *path);
static ngx_int_t ngx_http_dav_location(ngx_http_request_t *r, u_char *path);
static char *ngx_http_dav_access(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);


static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
    { ngx_string("off"), NGX_HTTP_DAV_OFF },
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_string("mkcol"), NGX_HTTP_MKCOL },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_dav_commands[] = {

    { ngx_string("dav_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, methods),
      &ngx_http_dav_methods_mask },

    { ngx_string("create_full_put_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, create_full_put_path),
      NULL },

    { ngx_string("dav_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_dav_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_dav_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_dav_init,                     /* postconfiguration */

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
    NULL,                                  /* init module */
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
    char                     *failed;
    size_t                    root;
    ngx_int_t                 rc;
    ngx_str_t                 path;
    ngx_file_info_t           fi;
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
        r->request_body_file_log_level = 0;

        rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_DELETE:

        if (r->headers_in.content_length_n > 0) {
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        rc = ngx_http_discard_body(r);

        if (rc != NGX_OK && rc != NGX_AGAIN) {
            return rc;
        }

        ngx_http_map_uri_to_path(r, &path, &root, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http delete filename: \"%s\"", path.data);

        if (ngx_file_info(path.data, &fi) != -1) {

            if (ngx_is_dir(&fi)) {

                if (r->uri.data[r->uri.len - 1] != '/'
                    || r->headers_in.depth == NULL
                    || r->headers_in.depth->value.len != sizeof("infinity") - 1
                    || ngx_strcmp(r->headers_in.depth->value.data, "infinity")
                       != 0)
                {
                    return NGX_HTTP_BAD_REQUEST;
                }

                if (ngx_delete_dir(path.data) != NGX_FILE_ERROR) {
                    return NGX_HTTP_NO_CONTENT;
                }

                failed = ngx_delete_dir_n;

            } else {

                if (r->uri.data[r->uri.len - 1] == '/') {
                    return NGX_HTTP_BAD_REQUEST;
                }

                if (r->headers_in.depth
                    && r->headers_in.depth->value.len == 1
                    && r->headers_in.depth->value.data[0] == '1')
                {
                    return NGX_HTTP_BAD_REQUEST;
                }

                if (ngx_delete_file(path.data) != NGX_FILE_ERROR) {
                    return NGX_HTTP_NO_CONTENT;
                }

                failed = ngx_delete_file_n;
            }

        } else {
            failed = ngx_file_info_n;
        }

        return ngx_http_dav_error(r, ngx_errno, NGX_HTTP_NOT_FOUND, failed,
                                  path.data);

    case NGX_HTTP_MKCOL:

        if (r->uri.data[r->uri.len - 1] != '/') {
            return NGX_DECLINED;
        }

        if (r->headers_in.content_length_n > 0) {
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        rc = ngx_http_discard_body(r);

        if (rc != NGX_OK && rc != NGX_AGAIN) {
            return rc;
        }

        ngx_http_map_uri_to_path(r, &path, &root, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http mkcol path: \"%s\"", path.data);

        if (ngx_create_dir(path.data, dlcf->access) != NGX_FILE_ERROR) {
            if (ngx_http_dav_location(r, path.data) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_HTTP_CREATED;
        }

        return ngx_http_dav_error(r, ngx_errno, NGX_HTTP_CONFLICT,
                                  ngx_create_dir_n, path.data);
    }

    return NGX_DECLINED;
}


static void
ngx_http_dav_put_handler(ngx_http_request_t *r)
{
    char                     *failed;
    u_char                   *name;
    size_t                    root;
    time_t                    date;
    ngx_err_t                 err;
    ngx_str_t                *temp, path;
    ngx_uint_t                status;
    ngx_file_info_t           fi;
    ngx_http_dav_loc_conf_t  *dlcf;

    ngx_http_map_uri_to_path(r, &path, &root, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (ngx_file_info(path.data, &fi) == -1) {
        status = NGX_HTTP_CREATED;

    } else {
        status = NGX_HTTP_NO_CONTENT;

        if (ngx_is_dir(&fi)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                          "\"%s\" could not be created", path.data);

            if (ngx_delete_file(temp->data) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                              ngx_delete_file_n " \"%s\" failed",
                              temp->data);
            }

            ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

#if !(NGX_WIN32)

    if (ngx_change_file_access(temp->data, dlcf->access & ~0111)
        == NGX_FILE_ERROR)
    {
        err = ngx_errno;
        failed = ngx_change_file_access_n;
        name = temp->data;

        goto failed;
    }

#endif

    if (r->headers_in.date) {
        date = ngx_http_parse_time(r->headers_in.date->value.data,
                                   r->headers_in.date->value.len);

        if (date != NGX_ERROR) {
            if (ngx_set_file_time(temp->data,
                                  r->request_body->temp_file->file.fd, date)
                != NGX_OK)
            {
                err = ngx_errno;
                failed = ngx_set_file_time_n;
                name = temp->data;

                goto failed;
            }
        }
    }

    failed = ngx_rename_file_n;
    name = path.data;

    if (ngx_rename_file(temp->data, path.data) != NGX_FILE_ERROR) {
        goto ok;
    }

    err = ngx_errno;

    if (err == NGX_ENOENT) {

        if (dlcf->create_full_put_path) {
            err = ngx_create_full_path(path.data, dlcf->access);

            if (err == 0) {
                if (ngx_rename_file(temp->data, path.data) != NGX_FILE_ERROR) {
                    goto ok;
                }

                err = ngx_errno;
            }
        }
    }

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

failed:

    if (ngx_delete_file(temp->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed",
                      temp->data);
    }

    ngx_http_finalize_request(r,
                  ngx_http_dav_error(r, err, NGX_HTTP_CONFLICT, failed, name));

    return;

ok:

    if (status == NGX_HTTP_CREATED) {
        if (ngx_http_dav_location(r, path.data) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));
    return;
}


static ngx_int_t
ngx_http_dav_error(ngx_http_request_t *r, ngx_err_t err, ngx_int_t not_found,
    char *failed, u_char *path)
{
    ngx_int_t   rc;
    ngx_uint_t  level;

    if (err == NGX_ENOENT || err == NGX_ENOTDIR || err == NGX_ENAMETOOLONG) {
        level = NGX_LOG_ERR;
        rc = not_found;

    } else if (err == NGX_EACCES || err == NGX_EPERM) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_FORBIDDEN;

    } else if (err == NGX_EEXIST) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_NOT_ALLOWED;

    } else if (err == NGX_ENOSPC) {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INSUFFICIENT_STORAGE;

    } else {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(level, r->connection->log, err,
                  "%s \"%s\" failed", failed, path);

    return rc;
}


static ngx_int_t
ngx_http_dav_location(ngx_http_request_t *r, u_char *path)
{
    u_char                    *location;
    ngx_http_core_loc_conf_t  *clcf;

    r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!clcf->alias && clcf->root_lengths == NULL) {
        location = path + clcf->root.len;

    } else {
        location = ngx_palloc(r->pool, r->uri.len);
        if (location == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(location, r->uri.data, r->uri.len);
    }

    /*
     * we do not need to set the r->headers_out.location->hash and
     * r->headers_out.location->key fields
     */

    r->headers_out.location->value.len = r->uri.len;
    r->headers_out.location->value.data = location;

    return NGX_OK;
}


static char *
ngx_http_dav_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_loc_conf_t *lcf = conf;

    u_char      *p;
    ngx_str_t   *value;
    ngx_uint_t   i, right, shift;

    if (lcf->access != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lcf->access = 0700;

    for (i = 1; i < 3; i++) {

        p = value[i].data;

        if (ngx_strncmp(p, "user:", sizeof("user:") - 1) == 0) {
            shift = 6;
            p += sizeof("user:") - 1;

        } else if (ngx_strncmp(p, "group:", sizeof("group:") - 1) == 0) {
            shift = 3;
            p += sizeof("group:") - 1;

        } else if (ngx_strncmp(p, "all:", sizeof("all:") - 1) == 0) {
            shift = 0;
            p += sizeof("all:") - 1;

        } else {
            goto invalid;
        }

        if (ngx_strcmp(p, "rw") == 0) {
            right = 7;

        } else if (ngx_strcmp(p, "r") == 0) {
            right = 5;

        } else {
            goto invalid;
        }

        lcf->access += right << shift;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
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

    conf->create_full_put_path = NGX_CONF_UNSET;
    conf->access = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t  *prev = parent;
    ngx_http_dav_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_OFF));

    ngx_conf_merge_value(conf->create_full_put_path, prev->create_full_put_path,
                         0);

    ngx_conf_merge_uint_value(conf->access, prev->access, 0600);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dav_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_handler;

    return NGX_OK;
}
