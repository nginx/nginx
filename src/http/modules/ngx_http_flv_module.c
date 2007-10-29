
/*
 * Copyright (C) Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_flv_commands[] = {

    { ngx_string("flv"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_flv,
      0,
      0,
      NULL },

      ngx_null_command
};


static u_char  ngx_flv_header[] = "FLV\x1\x1\0\0\0\x9\0\0\0\x9";


static ngx_http_module_t  ngx_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_http_flv_module = {
    NGX_MODULE_V1,
    &ngx_http_flv_module_ctx,      /* module context */
    ngx_http_flv_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_flv_handler(ngx_http_request_t *r)
{
    u_char                    *p;
    off_t                      start, len;
    size_t                     root;
    ngx_fd_t                   fd;
    ngx_int_t                  rc;
    ngx_uint_t                 level, i;
    ngx_str_t                  path;
    ngx_err_t                  err;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out[2];
    ngx_file_info_t            fi;
    ngx_pool_cleanup_t        *cln;
    ngx_pool_cleanup_file_t   *clnf;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    /* TODO: Win32 */
    if (r->zero_in_uri) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%s\"", path.data);

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
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

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, err,
                          ngx_open_file_n " \"%s\" failed", path.data);
        }

        return rc;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", path.data);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!ngx_is_file(&fi)) {

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    start = 0;
    len = ngx_file_size(&fi);
    i = 1;

    if (r->args.len) {
        p = (u_char *) ngx_strnstr(r->args.data, "start=", r->args.len);

        if (p) {
            p += 6;

            start = ngx_atoof(p, r->args.len - (p - r->args.data));

            if (start == NGX_ERROR || start >= len) {
                start = 0;
            }

            if (start) {
                len = sizeof(ngx_flv_header) - 1 + len - start;
                i = 0;
            }
        }
    }

    log->action = "sending flv to client";

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;

    clnf->fd = fd;
    clnf->name = path.data;
    clnf->log = r->pool->log;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = ngx_file_mtime(&fi);

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (i == 0) {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = ngx_flv_header;
        b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];

    } else {
        r->allow_ranges = 1;
    }


    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = start;
    b->file_last = ngx_file_size(&fi);

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = 1;
    b->last_in_chain = 1;

    b->file->fd = fd;
    b->file->name = path;
    b->file->log = log;

    out[1].buf = b;
    out[1].next = NULL;

    return ngx_http_output_filter(r, &out[i]);
}


static char *
ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flv_handler;

    return NGX_CONF_OK;
}
