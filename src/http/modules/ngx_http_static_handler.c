
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
    ngx_chain_t *ch;

/*
    ngx_http_event_static_handler_loc_conf_t  *cf;

    cf = (ngx_http_event_static_handler_loc_conf_t *)
             ngx_get_module_loc_conf(r, &ngx_http_event_static_handler_module);

*/

    r->fd = ngx_open_file(r->filename, NGX_FILE_RDONLY);
    if (r->fd == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_static_handler: "
                      ngx_open_file_n " %s failed", r->filename);
        /* STUB */
        return -1;
    }

    if (ngx_stat_fd(r->fd, &r->file_info) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_static_handler: "
                      ngx_stat_fd_n " %s failed", r->filename);
        /* STUB */
        return -1;
    }

    r->headers_out->status = NGX_HTTP_OK;
    r->headers_out->content_length = ngx_file_size(r->file_info);
/*
    r->headers_out->last_modified = ngx_file_mtime(r->file_info);
*/

    /* STUB */
    r->headers_out->content_type = "text/html";

    /* STUB */
    rc = ngx_http_header_filter(r);
/*
    rc = ngx_send_http_header(r->headers_out);
*/
    if (r->header_only)
        return rc;

    /* TODO: NGX_HTTP_INTERNAL_SERVER_ERROR is too late */

    /* STUB */
    ngx_test_null(h, ngx_get_hunk(r->pool, 1024, 0, 64),
                  /* STUB */
                  -1);
/*
    ngx_test_null(h, ngx_create_hunk(r->pool), NGX_HTTP_INTERNAL_SERVER_ERROR);
*/
    h->type = NGX_HUNK_FILE|NGX_HUNK_LAST;
    h->fd = r->fd;
    h->pos.file = 0;
    h->last.file = ngx_file_size(r->file_info);

    /* STUB */
    ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)),
                  /* STUB */
                  -1);
/*
                  NGX_HTTP_FILTER_ERROR);
*/

/*
    ngx_test_null(ch, ngx_create_chain(r->pool),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);
*/
    ch->hunk = h;
    ch->next = NULL;

    /* STUB */
    rc = ngx_http_write_filter(r, ch);
    ngx_log_debug(r->connection->log, "write_filter: %d" _ rc);
    return rc;
/*
    return ngx_http_filter(r, ch);
*/
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
