
#include <ngx_config.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_http.h>

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
    int rc;
    ngx_hunk_t  *h;
    ngx_http_log_ctx_t  *ctx;

/*
    ngx_http_event_static_handler_loc_conf_t  *cf;

    cf = (ngx_http_event_static_handler_loc_conf_t *)
             ngx_get_module_loc_conf(r, &ngx_http_event_static_handler_module);

*/

    ngx_http_discard_body(r);
    ctx = r->connection->log->data;
    ctx->action = "sending response";

    r->fd = ngx_open_file(r->filename, NGX_FILE_RDONLY);
    if (r->fd == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_static_handler: "
                      ngx_open_file_n " %s failed", r->filename);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_stat_fd(r->fd, &r->fileinfo) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_static_handler: "
                      ngx_stat_fd_n " %s failed", r->filename);

        /* close fd */
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length = ngx_file_size(r->fileinfo);
/*
    r->headers_out.last_modified = ngx_file_mtime(r->fileinfo);
*/

    /* STUB */
    if (r->exten) {
        if (strcasecmp(r->exten, "html") == 0)
            r->headers_out.content_type = "text/html; charset=koi8-r";
        else if (strcasecmp(r->exten, "gif") == 0)
            r->headers_out.content_type = "image/gif";
        else if (strcasecmp(r->exten, "jpg") == 0)
            r->headers_out.content_type = "image/jpeg";
        else if (strcasecmp(r->exten, "pdf") == 0)
            r->headers_out.content_type = "application/pdf";

    } else {
        r->headers_out.content_type = "text/html; charset=koi8-r";
    }

    /* STUB */
    rc = ngx_http_header_filter(r);
/*
    rc = ngx_send_http_header(r->headers_out);
*/
    if (r->header_only)
        return rc;

    /* TODO: NGX_HTTP_INTERNAL_SERVER_ERROR is too late */

    /* STUB */
    ngx_test_null(h, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    h->type = NGX_HUNK_FILE|NGX_HUNK_LAST;
    h->pos.file = 0;
    h->last.file = ngx_file_size(r->fileinfo);

    /* STUB */
    ngx_test_null(h->file, ngx_pcalloc(r->pool, sizeof(ngx_file_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);
    h->file->fd = r->fd;
    h->file->log = r->connection->log;

    rc = ngx_http_output_filter(r, h);
    ngx_log_debug(r->connection->log, "0 output_filter: %d" _ rc);
    return rc;
}

#if 0

static void *ngx_create_index_config()
{
    ngx_http_index_handler_loc_conf_t  *cf;

    ngx_check_null(cf, ngx_alloc(p, sizeof(ngx_http_index_handler_loc_conf)),
                   NULL);

    cf->indices = ngx_create_array(p, sizeof(ngx_http_index_t), 5);
    if (cf->indices == NULL)
        return NULL;

    cf->max_index_len = 0;

    return cf;
}

static void *ngx_merge_index_config()
{
    if (p->indices->nelts > 0) {

        copy and check dups

        if (c->max_index_len < c->max_index_len)
            c->max_index_len < c->max_index_len);
    }
}

static void *ngx_set_index()
{
    if (*conf == NULL) {
        cf = ngx_create_index_conf();
        if (cf == NULL)
            return "can not create config";
    }

    while (args) {
       index = ngx_push_array(cf->indices);
       index->name = arg;
       index->len = ngx_strlen(arg) + 1;

       if (cf->max_index_len < index->len)
           cf->max_index_len = index->len;
    }

    *conf = cf;
}

#endif
