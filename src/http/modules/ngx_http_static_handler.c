
#include <ngx_config.h>

#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_http.h>
#include <ngx_http_output_filter.h>

ngx_http_module_t  ngx_http_static_module;


#if 0
/* STUB */
static ngx_http_static_ctx_t module_ctx;

void ngx_http_static_init()
{
     module_ctx.out = NULL;

     ngx_http_static_module.ctx = &module_ctx;
}
/* */
#endif


int ngx_http_static_handler(ngx_http_request_t *r)
{
    int  rc;
    ngx_err_t    err;
    ngx_hunk_t  *h;
    ngx_http_log_ctx_t  *ctx;

#if 0
    ngx_http_event_static_handler_loc_conf_t  *cf;

    cf = (ngx_http_event_static_handler_loc_conf_t *)
             ngx_get_module_loc_conf(r, &ngx_http_event_static_handler_module);

#endif

    ngx_http_discard_body(r);
    ctx = r->connection->log->data;
    ctx->action = "sending response";

    if (r->file.fd == NGX_INVALID_FILE)
        r->file.fd = ngx_open_file(r->file.name.data, NGX_FILE_RDONLY);

    if (r->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_static_handler: "
                      ngx_open_file_n " %s failed", r->file.name.data);

        if (err == NGX_ENOENT)
            return NGX_HTTP_NOT_FOUND;
#if (WIN32)
        else if (err == ERROR_PATH_NOT_FOUND)
            return NGX_HTTP_NOT_FOUND;
#endif
        else
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!r->file.info_valid) {
        if (ngx_stat_fd(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "ngx_http_static_handler: "
                          ngx_stat_fd_n " %s failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR)
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "ngx_http_static_handler: "
                              ngx_close_file_n " %s failed", r->file.name.data);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.info_valid = 1;
    }

#if !(WIN32) /* it's probably Unix specific */

    if (!ngx_is_file(r->file.info)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_static_handler: "
                      "%s is not regular file", r->file.name.data);

        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR)
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "ngx_http_static_handler: "
                          ngx_close_file_n " %s failed", r->file.name.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length = ngx_file_size(r->file.info);
    r->headers_out.last_modified_time = ngx_file_mtime(r->file.info);

    ngx_test_null(r->headers_out.content_type,
                  ngx_push_table(r->headers_out.headers),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    r->headers_out.content_type->key.len = 12;
    r->headers_out.content_type->key.data = "Content-Type";

    /* STUB */
    if (r->exten.len) {
        if (ngx_strcasecmp(r->exten.data, "html") == 0) {
            r->headers_out.content_type->value.len = 25;
            r->headers_out.content_type->value.data =
                                                   "text/html; charset=koi8-r";
        } else if (ngx_strcasecmp(r->exten.data, "gif") == 0) {
            r->headers_out.content_type->value.len = 9;
            r->headers_out.content_type->value.data = "image/gif";
        } else if (ngx_strcasecmp(r->exten.data, "jpg") == 0) {
            r->headers_out.content_type->value.len = 10;
            r->headers_out.content_type->value.data = "image/jpeg";
        } else if (ngx_strcasecmp(r->exten.data, "pdf") == 0) {
            r->headers_out.content_type->value.len = 15;
            r->headers_out.content_type->value.data = "application/pdf";
        }

    } else {
        r->headers_out.content_type->value.len = 25;
        r->headers_out.content_type->value.data = "text/html; charset=koi8-r";
    }
    /**/

    /* we need to allocate them before header would be sent */
    ngx_test_null(h, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    ngx_test_null(h->file, ngx_pcalloc(r->pool, sizeof(ngx_file_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    rc = ngx_http_send_header(r);
    if (r->header_only)
        return rc;

#if 0

    h->type = NGX_HUNK_FILE|NGX_HUNK_LAST;
    h->pos.file = 0;
    h->last.file = ngx_file_size(r->file.info);

    h->file->fd = r->file.fd;
    h->file->log = r->connection->log;

    rc = ngx_http_output_filter(r, h);

    ngx_log_debug(r->connection->log, "0 output_filter: %d" _ rc);

#else

#define BLK 10000

    {
    int  i, s;
    s = ngx_file_size(r->file.info);

    for (i = 0; i < s; i += BLK) {
        ngx_test_null(h, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        ngx_test_null(h->file, ngx_pcalloc(r->pool, sizeof(ngx_file_t)),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        h->type = NGX_HUNK_FILE;
        if (s - i <= BLK) {
            h->type |= NGX_HUNK_LAST;
        }

        h->pos.file = i;
        h->last.file = i + BLK;
        if (h->last.file > s) {
            h->last.file = s;
        }

        h->file->fd = r->file.fd;
        h->file->log = r->connection->log;

        rc = ngx_http_output_filter(r, h);

        ngx_log_debug(r->connection->log, "0 output_filter: %d" _ rc);
    }
    }

#endif

    return rc;
}
