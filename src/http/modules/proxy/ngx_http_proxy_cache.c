
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


static int ngx_http_proxy_process_cached_header(ngx_http_proxy_ctx_t *p);


int ngx_http_proxy_get_cached_response(ngx_http_proxy_ctx_t *p)
{
    int                              rc;
    char                            *last;
    ngx_http_request_t              *r;
    ngx_http_proxy_cache_t          *c;
    ngx_http_proxy_upstream_conf_t  *u;

    r = p->request;

    if (!(c = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_cache_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p->cache = c;

    c->ctx.file.fd = NGX_INVALID_FILE;
    c->ctx.file.log = r->connection->log;
    c->ctx.path = p->lcf->cache_path;

    u = p->lcf->upstream;

    c->ctx.key.len = u->url.len + r->uri.len - u->location->len + r->args.len;
    if (!(c->ctx.key.data = ngx_palloc(r->pool, c->ctx.key.len + 1))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_cpymem(c->ctx.key.data, u->url.data, u->url.len);

    last = ngx_cpymem(last, r->uri.data + u->location->len,
                      r->uri.len - u->location->len);

    if (r->args.len > 0) {
        *(last++) = '?';
        last = ngx_cpymem(last, r->args.data, r->args.len);
    }
    *last = '\0';

    p->header_in = ngx_create_temp_hunk(r->pool, p->lcf->header_buffer_size);
    if (p->header_in == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p->header_in->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;

    c->ctx.buf = p->header_in; 

    rc = ngx_http_cache_get_file(r, &c->ctx);

    if (rc == NGX_STALE) {
        p->stale = 1;
    }

    if (rc == NGX_OK || rc == NGX_STALE) {
        p->header_in->pos += c->ctx.header_size;
        if (ngx_http_proxy_process_cached_header(p) == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else if (rc == NGX_DECLINED) {
        p->header_in->pos += c->ctx.header_size;
        p->header_in->last = p->header_in->pos;
    }

    return rc;
}


static int ngx_http_proxy_process_cached_header(ngx_http_proxy_ctx_t *p)
{
    int                      rc, i;
    ngx_table_elt_t         *h;
    ngx_http_request_t      *r;
    ngx_http_proxy_cache_t  *c;

    rc = ngx_http_proxy_parse_status_line(p);

    c = p->cache;
    r = p->request;

    if (rc == NGX_AGAIN) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "\"proxy_header_buffer_size\" "
                      "is too small to read header from \"%s\"",
                      c->ctx.file.name.data);
        return NGX_ERROR;
    }

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no valid HTTP/1.0 header in \"%s\"",
                      c->ctx.file.name.data);
        return NGX_ERROR;
    }

    /* rc == NGX_OK */

    c->status = p->status;
    c->status_line.len = p->status_end - p->status_start;
    c->status_line.data = ngx_palloc(r->pool, c->status_line.len + 1);
    if (c->status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_cpystrn(c->status_line.data, p->status_start, c->status_line.len + 1);

    ngx_log_debug(r->connection->log, "http cache status %d '%s'" _ 
                  c->status _ c->status_line.data);

    c->headers_in.headers = ngx_create_table(r->pool, 20);

    for ( ;; ) {
        rc = ngx_http_parse_header_line(r, p->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_http_add_header(&c->headers_in, ngx_http_proxy_headers_in);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_palloc(r->pool,
                                     h->key.len + 1 + h->value.len + 1);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
            ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            for (i = 0; ngx_http_proxy_headers_in[i].name.len != 0; i++) {
                if (ngx_http_proxy_headers_in[i].name.len != h->key.len) {
                    continue;
                }

                if (ngx_strcasecmp(ngx_http_proxy_headers_in[i].name.data,
                                                             h->key.data) == 0)
                {
                    *((ngx_table_elt_t **) ((char *) &c->headers_in
                                   + ngx_http_proxy_headers_in[i].offset)) = h;
                    break;
                }
            }

            ngx_log_debug(r->connection->log, "HTTP cache header: '%s: %s'" _
                          h->key.data _ h->value.data);

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug(r->connection->log, "HTTP header done");

            return NGX_OK;

        } else if (rc == NGX_HTTP_PARSE_INVALID_HEADER) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "invalid header in \"%s\"",
                          c->ctx.file.name.data);
            return NGX_ERROR;
        }

        /* rc == NGX_AGAIN || rc == NGX_HTTP_PARSE_TOO_LONG_HEADER */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "\"proxy_header_buffer_size\" "
                      "is too small to read header from \"%s\"",
                      c->ctx.file.name.data);
        return NGX_ERROR;
    }
}


int ngx_http_proxy_send_cached_response(ngx_http_proxy_ctx_t *p)
{
    int                  rc;
    ngx_hunk_t          *h;
    ngx_chain_t          out;
    ngx_http_request_t  *r;

    r = p->request;

    r->headers_out.status = p->cache->status;

#if 0
    r->headers_out.content_length_n = -1;
    r->headers_out.content_length = NULL;
#endif

    /* copy an cached header to r->headers_out */
    
    if (ngx_http_proxy_copy_header(p, &p->cache->headers_in) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* we need to allocate all before the header would be sent */

    if (!((h = ngx_calloc_hunk(r->pool)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!((h->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t))))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    /* NEEDED ??? */ p->header_sent = 1;

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* TODO: part in p->header_in */

    h->type = r->main ? NGX_HUNK_FILE : NGX_HUNK_FILE|NGX_HUNK_LAST;

    h->file_pos = p->header_in->pos - p->header_in->start;
    h->file_last = h->file_pos + p->cache->ctx.header.length;

    h->file->fd = p->cache->ctx.file.fd;
    h->file->log = r->connection->log;
    
    out.hunk = h;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


int ngx_http_proxy_update_cache(ngx_http_proxy_ctx_t *p)
{
    if (p->cache == NULL) {
        return NGX_OK;
    }

    return ngx_http_cache_update_file(p->request, &p->cache->ctx,
                               &p->upstream->event_pipe->temp_file->file.name);
}
