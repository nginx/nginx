
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_http_header_t  ngx_http_headers_in[] = {
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host) },
    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection) },
    { ngx_string("If-Modified-Since"),
                         offsetof(ngx_http_headers_in_t, if_modified_since) },
    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent) },
    { ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer) },
    { ngx_string("Content-Length"),
                            offsetof(ngx_http_headers_in_t, content_length) },

    { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range) },
#if 0
    { ngx_string("If-Range"), offsetof(ngx_http_headers_in_t, if_range) },
#endif

#if (NGX_HTTP_GZIP)
    { ngx_string("Accept-Encoding"),
                           offsetof(ngx_http_headers_in_t, accept_encoding) },
#endif

    { ngx_string("Authorization"),
                             offsetof(ngx_http_headers_in_t, authorization) },

    { ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive) },

#if (NGX_HTTP_PROXY)
    { ngx_string("X-Forwarded-For"),
                           offsetof(ngx_http_headers_in_t, x_forwarded_for) },
#endif

    { ngx_null_string, 0 }
};


ngx_http_header_t  ngx_http_headers_out[] = {
    { ngx_string("Server"), offsetof(ngx_http_headers_out_t, server) },
    { ngx_string("Date"), offsetof(ngx_http_headers_out_t, date) },
    { ngx_string("Content-Type"),
                             offsetof(ngx_http_headers_out_t, content_type) },
    { ngx_string("Content-Length"),
                           offsetof(ngx_http_headers_out_t, content_length) },
    { ngx_string("Content-Encoding"),
                         offsetof(ngx_http_headers_out_t, content_encoding) },
    { ngx_string("Location"), offsetof(ngx_http_headers_out_t, location) },
    { ngx_string("Last-Modified"),
                            offsetof(ngx_http_headers_out_t, last_modified) },
    { ngx_string("Accept-Ranges"),
                            offsetof(ngx_http_headers_out_t, accept_ranges) },

    { ngx_null_string, 0 }
};


ngx_table_elt_t *ngx_http_add_header(void *header,
                                     ngx_http_header_t *http_headers)
{
    void             *prev;
    ngx_uint_t        i, j;
    ngx_table_t      *headers;
    ngx_table_elt_t  *h, *new;

    headers = header;

    prev = headers->elts;

    if (!(new = ngx_push_table(headers))) {
        return NULL;
    }

    if (prev == headers->elts) {
        return new;
    }

    /*
     * When table is relocated we need to update pointers in r->headers_in,
     * r->headers_out, etc.  However this relocation should be very rare
     * because we preallocate enough space for the number of the real world
     * HTTP headers.
     */

    ngx_log_error(NGX_LOG_ALERT, headers->pool->log, 0,
                  "header table is small, %d elements", headers->nelts - 1);

    h = headers->elts;
    for (i = 0; i < headers->nelts - 1; i++) {
        if (h[i].key.len == 0) {
            continue;
        }

        for (j = 0; http_headers[j].name.len != 0; j++) {
            if (http_headers[j].name.len != h[i].key.len) {
                continue;
            }

            if (ngx_strcasecmp(http_headers[j].name.data, h[i].key.data) == 0) {
                *((ngx_table_elt_t **)
                      ((char *) header + http_headers[j].offset)) = &h[i];
                break;
            }
        }
    }

    return new;
}

