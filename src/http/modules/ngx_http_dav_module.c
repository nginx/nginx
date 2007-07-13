
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DAV_COPY_BLOCK      65536

#define NGX_HTTP_DAV_OFF             2


#define NGX_HTTP_DAV_NO_DEPTH        -3
#define NGX_HTTP_DAV_INVALID_DEPTH   -2
#define NGX_HTTP_DAV_INFINITY_DEPTH  -1


typedef struct {
    ngx_uint_t  methods;
    ngx_flag_t  create_full_put_path;
    ngx_uint_t  access;
} ngx_http_dav_loc_conf_t;


typedef struct {
    ngx_str_t   path;
    size_t      len;
} ngx_http_dav_copy_ctx_t;


static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);

static void ngx_http_dav_put_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_no_init(void *ctx, void *prev);
static ngx_int_t ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);

static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r,
    ngx_http_dav_loc_conf_t *dlcf);

static ngx_int_t ngx_http_dav_copy_move_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_copy_dir_time(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_http_dav_copy_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);

static ngx_int_t ngx_http_dav_delete_path(ngx_http_request_t *r,
    ngx_str_t *path, ngx_uint_t dir);
static ngx_int_t ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt);
static ngx_int_t ngx_http_dav_error(ngx_log_t *log, ngx_err_t err,
    ngx_int_t not_found, char *failed, u_char *path);
static ngx_int_t ngx_http_dav_location(ngx_http_request_t *r, u_char *path);
static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);


static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
    { ngx_string("off"), NGX_HTTP_DAV_OFF },
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_string("mkcol"), NGX_HTTP_MKCOL },
    { ngx_string("copy"), NGX_HTTP_COPY },
    { ngx_string("move"), NGX_HTTP_MOVE },
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
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, access),
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
    ngx_int_t                 rc;
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
            return NGX_HTTP_BAD_REQUEST;
        }

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_DELETE:

        return ngx_http_dav_delete_handler(r);

    case NGX_HTTP_MKCOL:

        return ngx_http_dav_mkcol_handler(r, dlcf);

    case NGX_HTTP_COPY:

        return ngx_http_dav_copy_move_handler(r);

    case NGX_HTTP_MOVE:

        return ngx_http_dav_copy_move_handler(r);
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
    ngx_uint_t                status, not_found;
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

    if (ngx_change_file_access(temp->data, dlcf->access) == NGX_FILE_ERROR) {
        err = ngx_errno;
        not_found = NGX_HTTP_INTERNAL_SERVER_ERROR;
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
                not_found = NGX_HTTP_INTERNAL_SERVER_ERROR;
                failed = ngx_set_file_time_n;
                name = temp->data;

                goto failed;
            }
        }
    }

    not_found = NGX_HTTP_CONFLICT;
    failed = ngx_rename_file_n;
    name = path.data;

    if (ngx_rename_file(temp->data, path.data) != NGX_FILE_ERROR) {
        goto ok;
    }

    err = ngx_errno;

    if (err == NGX_ENOENT) {

        if (dlcf->create_full_put_path) {
            err = ngx_create_full_path(path.data, ngx_dir_access(dlcf->access));

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
                              ngx_http_dav_error(r->connection->log, err,
                                                 not_found, failed, name));

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
ngx_http_dav_delete_handler(ngx_http_request_t *r)
{
    size_t           root;
    ngx_int_t        rc, depth;
    ngx_uint_t       dir;
    ngx_str_t        path;
    ngx_file_info_t  fi;

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

    if (ngx_file_info(path.data, &fi) == -1) {
        return ngx_http_dav_error(r->connection->log, ngx_errno,
                                  NGX_HTTP_NOT_FOUND, ngx_file_info_n,
                                  path.data);
    }

    if (ngx_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            /* TODO: 301 */
            return NGX_HTTP_BAD_REQUEST;
        }

        depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);

        if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            return NGX_HTTP_BAD_REQUEST;
        }

        path.len -= 2;  /* omit "/\0" */

        dir = 1;

    } else {

        depth = ngx_http_dav_depth(r, 0);

        if (depth != 0 && depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            return NGX_HTTP_BAD_REQUEST;
        }

        dir = 0;
    }

    rc = ngx_http_dav_delete_path(r, &path, dir);

    if (rc == NGX_OK) {
        return NGX_HTTP_NO_CONTENT;
    }

    return rc;
}


static ngx_int_t
ngx_http_dav_no_init(void *ctx, void *prev)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete dir: \"%s\"", path->data);

    if (ngx_delete_dir(path->data) == NGX_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_dir_n,
                                  path->data);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete file: \"%s\"", path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_file_n,
                                  path->data);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_mkcol_handler(ngx_http_request_t *r, ngx_http_dav_loc_conf_t *dlcf)
{
    size_t     root;
    ngx_int_t  rc;
    ngx_str_t  path;

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

    if (ngx_create_dir(path.data, ngx_dir_access(dlcf->access))
        != NGX_FILE_ERROR)
    {
        if (ngx_http_dav_location(r, path.data) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_HTTP_CREATED;
    }

    return ngx_http_dav_error(r->connection->log, ngx_errno,
                              NGX_HTTP_BAD_REQUEST, ngx_create_dir_n,
                              path.data);
}


static ngx_int_t
ngx_http_dav_copy_move_handler(ngx_http_request_t *r)
{
    u_char                   *p, *host, *last, ch;
    size_t                    root;
    ngx_err_t                 err;
    ngx_int_t                 rc, depth;
    ngx_uint_t                overwrite, slash;
    ngx_str_t                 path, uri;
    ngx_tree_ctx_t            tree;
    ngx_file_info_t           fi;
    ngx_table_elt_t          *dest, *over;
    ngx_http_dav_copy_ctx_t   copy;

    if (r->headers_in.content_length_n > 0) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dest = r->headers_in.destination;

    if (dest == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (dest->value.len < sizeof("http://") - 1 + r->server_name.len + 1) {
        goto invalid_destination;
    }

#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        if (ngx_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("https://") - 1;

    } else
#endif
    {
        if (ngx_strncmp(dest->value.data, "http://", sizeof("http://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("http://") - 1;
    }

    if (ngx_strncmp(host, r->server_name.data, r->server_name.len) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Destination URI \"%V\" is handled by "
                      "different repository than the source URI",
                      &dest->value);

        return NGX_HTTP_BAD_REQUEST;
    }

    last = dest->value.data + dest->value.len;

    for (p = host + r->server_name.len; p < last; p++) {
        if (*p == '/') {
            goto destination_done;
        }
    }

invalid_destination:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Destination\" header: \"%V\"",
                  &dest->value);

    return NGX_HTTP_BAD_REQUEST;

destination_done:

    depth = ngx_http_dav_depth(r, 0);

    if (depth != 0 && depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
        return NGX_HTTP_BAD_REQUEST;
    }

    over = r->headers_in.overwrite;

    if (over) {
        if (over->value.len == 1) {
            ch = over->value.data[0];

            if (ch == 'T' || ch == 't') {
                overwrite = 1;
                goto overwrite_done;
            }

            if (ch == 'F' || ch == 'f') {
                overwrite = 0;
                goto overwrite_done;
            }

        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Overwrite\" header: \"%V\"",
                      &over->value);

        return NGX_HTTP_BAD_REQUEST;
    }

    overwrite = 1;

overwrite_done:

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    ngx_http_map_uri_to_path(r, &path, &root, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy from: \"%s\"", path.data);

    uri = r->uri;

    r->uri.len = last - p;
    r->uri.data = p;

    ngx_http_map_uri_to_path(r, &copy.path, &root, 0);

    r->uri = uri;

    copy.path.len--;  /* omit "\0" */

    if (copy.path.data[copy.path.len - 1] == '/') {
        slash = 1;
        copy.path.len--;
        copy.path.data[copy.path.len] = '\0';

    } else {
        slash = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy to: \"%s\"", copy.path.data);

    if (ngx_file_info(copy.path.data, &fi) == -1) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            return ngx_http_dav_error(r->connection->log, err,
                                      NGX_HTTP_NOT_FOUND, ngx_file_info_n,
                                      copy.path.data);
        }

        /* destination does not exist */

    } else {

        /* destination exists */

        if (ngx_is_dir(&fi) && !slash) {
            return NGX_HTTP_CONFLICT;
        }

        if (!overwrite) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http delete: \"%s\"", copy.path.data);

        rc = ngx_http_dav_delete_path(r, &copy.path, ngx_is_dir(&fi));

        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (ngx_file_info(path.data, &fi) == -1) {
        return ngx_http_dav_error(r->connection->log, ngx_errno,
                                  NGX_HTTP_NOT_FOUND, ngx_file_info_n,
                                  path.data);
    }


    if (ngx_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            /* TODO: 301 */
            return NGX_HTTP_BAD_REQUEST;
        }

        path.len -= 2;  /* omit "/\0" */

        if (r->method == NGX_HTTP_MOVE) {
            if (ngx_rename_file(path.data, copy.path.data) != NGX_FILE_ERROR) {
                return NGX_HTTP_CREATED;
            }
        }

        if (ngx_create_dir(copy.path.data, ngx_file_access(&fi))
            == NGX_FILE_ERROR)
        {
            return ngx_http_dav_error(r->connection->log, ngx_errno,
                                      NGX_HTTP_NOT_FOUND,
                                      ngx_create_dir_n, copy.path.data);
        }

        copy.len = path.len;

        tree.init_handler = ngx_http_dav_no_init;
        tree.file_handler = ngx_http_dav_copy_file;
        tree.pre_tree_handler = ngx_http_dav_copy_dir;
        tree.post_tree_handler = ngx_http_dav_copy_dir_time;
        tree.spec_handler = ngx_http_dav_noop;
        tree.data = &copy;
        tree.alloc = 0;
        tree.log = r->connection->log;

        if (ngx_walk_tree(&tree, &path) == NGX_OK) {

            if (r->method == NGX_HTTP_MOVE) {
                rc = ngx_http_dav_delete_path(r, &path, 1);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            return NGX_HTTP_CREATED;
        }

    } else {

        if (dest->value.data[dest->value.len - 1] == '/') {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (r->method == NGX_HTTP_MOVE) {
            if (ngx_rename_file(path.data, copy.path.data) != NGX_FILE_ERROR) {
                return NGX_HTTP_NO_CONTENT;
            }
        }

        tree.data = &copy;
        tree.log = r->connection->log;

        if (ngx_http_dav_copy_file(&tree, &path) != NGX_FILE_ERROR) {

            if (r->method == NGX_HTTP_MOVE) {
                rc = ngx_http_dav_delete_path(r, &path, 0);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            return NGX_HTTP_NO_CONTENT;
        }
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_http_dav_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir to: \"%s\"", dir);

    if (ngx_create_dir(dir, ngx_dir_access(ctx->access)) == NGX_FILE_ERROR) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_create_dir_n,
                                  dir);
    }

    ngx_free(dir);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_copy_dir_time(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    ngx_http_dav_copy_ctx_t  *copy;
#if (WIN32)
    ngx_fd_t                  fd;
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time to: \"%s\"", dir);

#if (WIN32)

    fd = ngx_open_file(dir, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_open_file_n, dir);
        goto failed;
    }

    if (ngx_set_file_time(NULL, fd, ctx->mtime) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_set_file_time_n " \"%s\" failed", dir);
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", dir);
    }

failed:

#else

    if (ngx_set_file_time(dir, 0, ctx->mtime) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_set_file_time_n " \"%s\" failed", dir);
    }

#endif

    ngx_free(dir);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_copy_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *file;
    size_t                    len;
    off_t                     size;
    ssize_t                   n;
    ngx_fd_t                  fd, copy_fd;
    ngx_http_dav_copy_ctx_t  *copy;
    u_char                    buf[NGX_HTTP_DAV_COPY_BLOCK];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    file = ngx_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(file, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file to: \"%s\"", file);

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_open_file_n,
                                  path->data);
        goto failed;
    }

    copy_fd = ngx_open_file(file, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN,
                            ctx->access);

    if (copy_fd == NGX_INVALID_FILE) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_open_file_n,
                                  file);
        goto copy_failed;
    }

    for (size = ctx->size; size > 0; size -= n) {

        n = ngx_read_fd(fd, buf, NGX_HTTP_DAV_COPY_BLOCK);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                          ngx_read_fd_n " \"%s\" failed", path->data);
            break;
        }

        if (ngx_write_fd(copy_fd, buf, n) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                          ngx_write_fd_n " \"%s\" failed", file);
        }
    }

    if (ngx_set_file_time(file, copy_fd, ctx->mtime) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_set_file_time_n " \"%s\" failed", file);
    }

    if (ngx_close_file(copy_fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file);
    }

copy_failed:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", path->data);
    }

failed:

    ngx_free(file);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_delete_path(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir)
{
    char            *failed;
    ngx_tree_ctx_t   tree;

    if (dir) {

        tree.init_handler = ngx_http_dav_no_init;
        tree.file_handler = ngx_http_dav_delete_file;
        tree.pre_tree_handler = ngx_http_dav_noop;
        tree.post_tree_handler = ngx_http_dav_delete_dir;
        tree.spec_handler = ngx_http_dav_delete_file;
        tree.data = NULL;
        tree.alloc = 0;
        tree.log = r->connection->log;

        /* todo: 207 */

        if (ngx_walk_tree(&tree, path) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_delete_dir(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        failed = ngx_delete_dir_n;

    } else {

        if (ngx_delete_file(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        failed = ngx_delete_file_n;
    }

    return ngx_http_dav_error(r->connection->log, ngx_errno,
                              NGX_HTTP_NOT_FOUND, failed, path->data);
}


static ngx_int_t
ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt)
{
    ngx_table_elt_t  *depth;

    depth = r->headers_in.depth;

    if (depth == NULL) {
        return dflt;
    }

    if (depth->value.len == 1) {

        if (depth->value.data[0] == '0') {
            return 0;
        }

        if (depth->value.data[0] == '1') {
            return 1;
        }

    } else {

        if (depth->value.len == sizeof("infinity") - 1
            && ngx_strcmp(depth->value.data, "infinity") == 0)
        {
            return NGX_HTTP_DAV_INFINITY_DEPTH;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return NGX_HTTP_DAV_INVALID_DEPTH;
}


static ngx_int_t
ngx_http_dav_error(ngx_log_t *log, ngx_err_t err, ngx_int_t not_found,
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

    ngx_log_error(level, log, err, "%s \"%s\" failed", failed, path);

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
