
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


static int ngx_http_proxy_rewrite_location_header(ngx_http_proxy_ctx_t *p,
                                                  ngx_table_elt_t *loc);

int ngx_http_proxy_copy_header(ngx_http_proxy_ctx_t *p,
                               ngx_http_proxy_headers_in_t *headers_in)
{
    int                  i;
    ngx_table_elt_t     *ho, *h;
    ngx_http_request_t  *r;

    r = p->request;

    h = headers_in->headers->elts;
    for (i = 0; i < headers_in->headers->nelts; i++) {

        if (&h[i] == headers_in->connection) {
            continue;
        }
    
        if (p->accel) {
            if (&h[i] == headers_in->date
                || &h[i] == headers_in->accept_ranges) {
                continue;
            }

            if (&h[i] == headers_in->x_accel_expires
                && !p->lcf->pass_x_accel_expires)
            {
                continue;
            } 
    
            if (&h[i] == headers_in->server && !p->lcf->pass_server) {
                continue;
            } 
    
            if (&h[i] == headers_in->location) {
                if (ngx_http_proxy_rewrite_location_header(p, &h[i])
                                                                  == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                continue;
            } 
        }
    
        if (&h[i] == headers_in->content_type) {
            r->headers_out.content_type = &h[i];
            r->headers_out.content_type->key.len = 0;
            continue;
        }

        if (!(ho = ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
        {
            return NGX_ERROR;
        }
    
        *ho = h[i];
    
        /*
         * ngx_http_header_filter() does not handle specially
         * the following headers if they are set:
         *     r->headers_out.server,
         *     r->headers_out.date,
         *     r->headers_out.content_length
         */

        if (&h[i] == headers_in->server) {
            r->headers_out.server = ho;
            continue;
        }

        if (&h[i] == headers_in->date) {
            r->headers_out.date = ho;
            continue;
        }

        if (&h[i] == headers_in->content_length) {
            r->headers_out.content_length = ho;
            r->headers_out.content_length_n = ngx_atoi(ho->value.data,
                                                       ho->value.len);
            continue;
        }
    }

    return NGX_OK;
}


static int ngx_http_proxy_rewrite_location_header(ngx_http_proxy_ctx_t *p,
                                                  ngx_table_elt_t *loc)
{
    char                            *last;
    ngx_http_request_t              *r;
    ngx_http_proxy_upstream_conf_t  *uc;

    r = p->request;
    uc = p->lcf->upstream;

    r->headers_out.location = ngx_http_add_header(&r->headers_out,
                                                  ngx_http_headers_out);
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }

    if (uc->url.len > loc->value.len
        || ngx_rstrncmp(loc->value.data, uc->url.data, uc->url.len) != 0)
    {
        *r->headers_out.location = *loc;
        return NGX_OK;
    }

    /* TODO: proxy_reverse */

    r->headers_out.location->value.len = uc->location->len
                                         + (loc->value.len - uc->url.len) + 1;
    r->headers_out.location->value.data =
                       ngx_palloc(r->pool, r->headers_out.location->value.len); 

    if (r->headers_out.location->value.data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_cpymem(r->headers_out.location->value.data,
                      uc->location->data, uc->location->len);

    ngx_cpystrn(last, loc->value.data + uc->url.len,
                loc->value.len - uc->url.len + 1);

    return NGX_OK;
}
