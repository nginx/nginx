
#include <ngx_config.h>

#include <ngx_strings.h>
#include <ngx_open.h>
#include <ngx_stat.h>

#include <ngx_http.h>

int ngx_http_static_handler(ngx_http_request_t *r)
{
    int          index_len, err, i;
    char        *name, *loc, *file
    ngx_file_t   fd;

    ngx_http_header_out_t  out;
    ngx_http_event_static_handler_loc_conf_t  *cf;

    cf = (ngx_http_event_static_handler_loc_conf_t *)
             ngx_get_module_loc_conf(r, &ngx_http_event_static_handler_module);

    ngx_assert(r->fd, return NGX_HTTP_INTERNAL_SERVER_ERROR,
               r->connection->log, "ngx_http_static_handler: no file");

    out.status = NGX_HTTP_OK;
    out.content_length = r->stat.sb_size;
    out.last_modified = r->stat.sb_mtime;

    /* */
    out.content_type = "text/html";

    rc = ngx_send_http_header(&out);
    if (r->header_only)
        return rc;

    /* NGX_HTTP_INTERNAL_SERVER_ERROR is too late */

    ngx_test_null(h, ngx_create_hunk(r->pool), NGX_HTTP_INTERNAL_SERVER_ERROR);
    h->type = NGX_HUNK_FILE | NGX_HUNK_LAST;
    h->fd = r->fd;
    h->pos.file = 0;
    h->end.file = r->stat.sb_size;

    ngx_test_null(ch, ngx_create_chain(r->pool),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);
    ch->hunk = h;
    ch->next = NULL;

    return ngx_http_filter(ch);
}

/*

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

*/
