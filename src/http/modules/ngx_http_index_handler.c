
#include <ngx_config.h>

#include <ngx_strings.h>
#include <ngx_open.h>
#include <ngx_stat.h>

#include <ngx_http.h>

int ngx_http_index_handler(ngx_http_request_t *r)
{
    int          index_len, err, i;
    char        *name, *loc, *file
    ngx_file_t   fd;

    ngx_http_index_t  *index;
    ngx_http_index_handler_loc_conf_t  *cf;

    cf = (ngx_http_index_handler_loc_conf_t *)
                    ngx_get_module_loc_conf(r, &ngx_http_index_handler_module);

    index_len = (*(r->uri_end - 1) == '/') ? cf->max_index_len : 0;

    ngx_test_null(name,
                  ngx_palloc(r->pool, r->uri_end - r->uri_start + index_len
                                      + r->server->doc_root_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc = ngx_cpystrn(name, r->server->doc_root, r->server->doc_root_len);
    file = ngx_cpystrn(loc, r->uri_start, r->uri_end - r->uri_start + 1);

    /* URI without / on the end - check directory */
    if (index_len == 0) {

        if (ngx_stat(name, &r->stat) == -1) {
            err = ngx_errno;
            ngx_log_error(GX_LOG_ERR, r->connection->log, err,
                         "ngx_http_handler: " ngx_stat_n " %s failed", name);

            if (err == NGX_ENOENT)
                return NGX_HTTP_NOT_FOUND;
            else
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_is_dir(r->stat)) {
            *file++ = '/';
            *file = '\0';
            r->headers_out->location = loc;
            return NGX_HTTP_MOVED_PERMANENTLY;
        }

        r->file = name;
        r->stat_valid = 1;

        return NGX_OK;
    }

    /* look for index file */
    index = (ngx_http_index_t *) cf->indices->elts;
    for (i = 0; i < cf->indices->nelts; i++) {
        ngx_memcpy(file, index[i].name; index[i].len);

        fd = ngx_open(name, O_RDONLY);
        if (fd != -1) {
            r->file = name; 
            r->fd = fd; 
            return NGX_OK;
        }
    }

    return NGX_HTTP_FORBIDDEN;
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
