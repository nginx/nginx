
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static int ngx_http_header_filter_init(ngx_pool_t *pool);
static int ngx_http_header_filter(ngx_http_request_t *r);


static ngx_http_module_t  ngx_http_header_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_header_filter_module = {
    NGX_MODULE,
    &ngx_http_header_filter_module_ctx,    /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_header_filter_init            /* init module */
};


static char server_string[] = "Server: " NGINX_VER CRLF;


static ngx_str_t http_codes[] = {

    ngx_string("200 OK"),
    ngx_null_string,  /* "201 Created" */
    ngx_null_string,  /* "202 Accepted" */
    ngx_null_string,  /* "203 Non-Authoritative Information" */
    ngx_null_string,  /* "204 No Content" */
    ngx_null_string,  /* "205 Reset Content" */
    ngx_string("206 Partial Content"),
    ngx_null_string,  /* "207 Multi-Status" */

#if 0
    ngx_null_string,  /* "300 Multiple Choices" */
#endif

    ngx_string("301 Moved Permanently"),
#if 0
    ngx_string("302 Moved Temporarily"),
#else
    ngx_string("302 Found"),
#endif
    ngx_null_string,  /* "303 See Other" */
    ngx_string("304 Not Modified"),

    ngx_string("400 Bad Request"),
    ngx_string("401 Unauthorized"),
    ngx_null_string,  /* "402 Payment Required" */
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_null_string,  /* "406 Not Acceptable" */
    ngx_null_string,  /* "407 Proxy Authentication Required" */
    ngx_string("408 Request Time-out"),
    ngx_null_string,  /* "409 Conflict" */
    ngx_null_string,  /* "410 Gone" */
    ngx_string("411 Length Required"),
    ngx_null_string,  /* "412 Precondition Failed" */
    ngx_string("413 Request Entity Too Large"),
    ngx_null_string,  /* "414 Request-URI Too Large" but we never send it
                         because we treat such requests as the HTTP/0.9 requests
                         and send only the body without the header */
    ngx_null_string,  /* "415 Unsupported Media Type" */
    ngx_string("416 Requested Range Not Satisfiable"),

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Method Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out")
};



static int ngx_http_header_filter(ngx_http_request_t *r)
{
    int                len, status, i;
    time_t             ims;
    ngx_hunk_t        *h;
    ngx_chain_t       *ch;
    ngx_table_elt_t   *header;

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_OK;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    /* 9 is for "HTTP/1.x ", 2 is for trailing "\r\n"
       and 2 is for end of header */
    len = 9 + 2 + 2;

    if (r->headers_in.if_modified_since && r->headers_out.status == NGX_HTTP_OK)
    {
        /* TODO: check LM header */
        if (r->headers_out.last_modified_time) {
            ims = ngx_http_parse_time(
                                  r->headers_in.if_modified_since->value.data,
                                  r->headers_in.if_modified_since->value.len);

            ngx_log_debug(r->connection->log, "%d %d" _
                          ims _ r->headers_out.last_modified_time);

            /* I think that the date equality is correcter */
            if (ims != NGX_ERROR && ims == r->headers_out.last_modified_time) {
                r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
                r->headers_out.content_length = -1;
                r->headers_out.content_type->key.len = 0;
            }
        }
    }

    /* status line */
    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
#if (NGX_SUPPRESS_WARN)
        status = NGX_INVALID_ARRAY_INDEX;
#endif

    } else {
        if (r->headers_out.status < NGX_HTTP_MOVED_PERMANENTLY) {
            /* 2XX */
            status = r->headers_out.status - NGX_HTTP_OK;

        } else if (r->headers_out.status < NGX_HTTP_BAD_REQUEST) {
            /* 3XX */
            status = r->headers_out.status - NGX_HTTP_MOVED_PERMANENTLY + 8;
            r->header_only = 1;

        } else if (r->headers_out.status < NGX_HTTP_INTERNAL_SERVER_ERROR) {
            /* 4XX */
            status = r->headers_out.status - NGX_HTTP_BAD_REQUEST + 8 + 4;

        } else {
            /* 5XX */
            status = r->headers_out.status
                                 - NGX_HTTP_INTERNAL_SERVER_ERROR + 8 + 4 + 17;
        }

        len += http_codes[status].len;
    }

    if (r->headers_out.server && r->headers_out.server->key.len) {
        len += r->headers_out.server->key.len
               + r->headers_out.server->value.len + 2;
    } else {
        len += sizeof(server_string) - 1;
    }

    if (r->headers_out.date && r->headers_out.date->key.len) {
        len += r->headers_out.date->key.len
               + r->headers_out.date->value.len + 2;
    } else {
        /* "Date: ... \r\n" */
        len += 37;
    }

    if (r->headers_out.content_range && r->headers_out.content_range->value.len)
    {
        len += 15 + r->headers_out.content_range->value.len + 2;
    }

    if (r->headers_out.content_length >= 0) {
        /* "Content-Length: ... \r\n", 2^64 is 20 characters */
        len += 48;
    }

    if (r->headers_out.content_type && r->headers_out.content_type->value.len) {
        r->headers_out.content_type->key.len = 0;
        len += 16 + r->headers_out.content_type->value.len;

        if (r->headers_out.charset.len) {
            /* "; charset= ... " */
            len += 10 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        r->headers_out.location->key.len = 0;
        /* "Location: http:// ... \r\n" */
        len += 17 + r->server_name->len
               + r->headers_out.location->value.len + 2;

        if (r->port != 80) {
            len += r->port_name->len;
        }
    }

    if (r->headers_out.last_modified && r->headers_out.last_modified->key.len) {
        len += r->headers_out.last_modified->key.len
               + r->headers_out.last_modified->value.len + 2;

    } else if (r->headers_out.last_modified_time != -1) {
        /* "Last-Modified: ... \r\n" */
        len += 46;
    }

    if (r->chunked) {
        /* "Transfer-Encoding: chunked\r\n" */
        len += 28;
    }

    if (r->keepalive == 0) {
        /* "Connection: close\r\n" */
        len += 19;
    } else {
        /* "Connection: keep-alive\r\n" */
        len += 24;
    }

    header = (ngx_table_elt_t *) r->headers_out.headers->elts;
    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0) {
            continue;
        }

        len += header[i].key.len + 2 + header[i].value.len + 2;
    }

    ngx_test_null(h, ngx_create_temp_hunk(r->pool, len, 0, 64), NGX_ERROR);

    /* "HTTP/1.x " */
    h->last = ngx_cpymem(h->last, "HTTP/1.1 ", 9);

    /* status line */
    if (r->headers_out.status_line.len) {
        h->last = ngx_cpymem(h->last, r->headers_out.status_line.data,
                             r->headers_out.status_line.len);

    } else {
        h->last = ngx_cpymem(h->last, http_codes[status].data,
                             http_codes[status].len);
    }
    *(h->last++) = CR; *(h->last++) = LF;

    if (!(r->headers_out.server && r->headers_out.server->key.len)) {
        h->last = ngx_cpymem(h->last, server_string, sizeof(server_string) - 1);
    }

    if (!(r->headers_out.date && r->headers_out.date->key.len)) {
        h->last = ngx_cpymem(h->last, "Date: ", 6);
        h->last += ngx_http_get_time(h->last, time(NULL));
        *(h->last++) = CR; *(h->last++) = LF;
    }


    if (r->headers_out.content_range && r->headers_out.content_range->value.len)
    {
        h->last = ngx_cpymem(h->last, "Content-Range: ", 15);
        h->last = ngx_cpymem(h->last, r->headers_out.content_range->value.data,
                             r->headers_out.content_range->value.len);
        *(h->last++) = CR; *(h->last++) = LF;
    }

    /* 2^64 is 20 characters  */
    if (r->headers_out.content_length >= 0) {
        h->last += ngx_snprintf(h->last, 49,
                                "Content-Length: " OFF_FMT CRLF,
                                r->headers_out.content_length);
    }

    if (r->headers_out.content_type && r->headers_out.content_type->value.len) {
        h->last = ngx_cpymem(h->last, "Content-Type: ", 14);
        h->last = ngx_cpymem(h->last, r->headers_out.content_type->value.data,
                             r->headers_out.content_type->value.len);

        if (r->headers_out.charset.len) {
            h->last = ngx_cpymem(h->last, "; charset=", 10);
            h->last = ngx_cpymem(h->last, r->headers_out.charset.data,
                                 r->headers_out.charset.len);
        }

        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        h->last = ngx_cpymem(h->last, "Location: http://", 17);
        h->last = ngx_cpymem(h->last, r->server_name->data,
                             r->server_name->len);
        if (r->port != 80) {
            h->last = ngx_cpymem(h->last, r->port_name->data,
                                 r->port_name->len);
        }

        h->last = ngx_cpymem(h->last, r->headers_out.location->value.data,
                             r->headers_out.location->value.len);

        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (!(r->headers_out.last_modified && r->headers_out.last_modified->key.len)
        && r->headers_out.last_modified_time != -1)
    {
        h->last = ngx_cpymem(h->last, "Last-Modified: ", 15);
        h->last += ngx_http_get_time(h->last,
                                         r->headers_out.last_modified_time);
        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (r->chunked) {
        h->last = ngx_cpymem(h->last, "Transfer-Encoding: chunked" CRLF, 28);
    }

    if (r->keepalive == 0) {
        h->last = ngx_cpymem(h->last, "Connection: close" CRLF, 19);

    } else {
        h->last = ngx_cpymem(h->last, "Connection: keep-alive" CRLF, 24);
    }

    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0) {
            continue;
        }

        h->last = ngx_cpymem(h->last, header[i].key.data, header[i].key.len);
        *(h->last++) = ':' ; *(h->last++) = ' ' ;

        h->last = ngx_cpymem(h->last, header[i].value.data,
                             header[i].value.len);
        *(h->last++) = CR; *(h->last++) = LF;
    }

    /* STUB */
    *(h->last) = '\0';
    ngx_log_debug(r->connection->log, "%s\n" _ h->pos);
    /**/

    /* the end of HTTP header */
    *(h->last++) = CR; *(h->last++) = LF;

    if (r->header_only) {
        h->type |= NGX_HUNK_LAST;
    }

    ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

    ch->hunk = h;
    ch->next = NULL;

    return ngx_http_write_filter(r, ch);
}


static int ngx_http_header_filter_init(ngx_pool_t *pool)
{
    ngx_http_top_header_filter = ngx_http_header_filter;
    return NGX_OK;
}
