
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static int ngx_http_header_filter_init(ngx_cycle_t *cycle);
static int ngx_http_header_filter(ngx_http_request_t *r);


static ngx_http_module_t  ngx_http_header_filter_module_ctx = {
    NULL,                                  /* pre conf */

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
    ngx_http_header_filter_init,           /* init module */
    NULL                                   /* init child */
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
    char              *p;
    ngx_hunk_t        *h;
    ngx_chain_t       *ln;
    ngx_table_elt_t   *header;

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_OK;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    /* 2 is for trailing "\r\n" and 2 is for "\r\n" in the end of header */
    len = sizeof("HTTP/1.x ") - 1 + 2 + 2;

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

            if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
                r->header_only = 1;
            }

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
        len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n >= 0) {
            len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
        }
    }

    if (r->headers_out.content_type && r->headers_out.content_type->value.len) {
        r->headers_out.content_type->key.len = 0;
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type->value.len + 2;

        if (r->headers_out.charset.len) {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        r->headers_out.location->key.len = 0;
        len += sizeof("Location: http://") - 1
               + r->server_name->len + r->headers_out.location->value.len + 2;

        if (r->port != 80) {
            len += r->port_name->len;
        }
    }

    if (r->headers_out.last_modified && r->headers_out.last_modified->key.len) {
        len += r->headers_out.last_modified->key.len
               + r->headers_out.last_modified->value.len + 2;

    } else if (r->headers_out.last_modified_time != -1) {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;
    } else {
        len += sizeof("Connection: closed" CRLF) - 1;
    }

    header = r->headers_out.headers->elts;
    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0) {
            continue;
        }

        /* 2 is for ": " and 2 is for "\r\n" */
        len += header[i].key.len + 2 + header[i].value.len + 2;
    }

    if (!(h = ngx_create_temp_hunk(r->pool, len))) {
        return NGX_ERROR;
    }

    /* "HTTP/1.x " */
    h->last = ngx_cpymem(h->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

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
        h->last = ngx_cpymem(h->last, "Date: ", sizeof("Date: ") - 1);
        h->last = ngx_cpymem(h->last, ngx_cached_http_time.data,
                             ngx_cached_http_time.len);

        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n >= 0) {
            h->last += ngx_snprintf(h->last,
                                sizeof("Content-Length: ") + NGX_OFF_T_LEN + 2,
                                "Content-Length: " OFF_T_FMT CRLF,
                                r->headers_out.content_length_n);
        }
    }

    if (r->headers_out.content_type && r->headers_out.content_type->value.len) {
        h->last = ngx_cpymem(h->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = h->last;
        h->last = ngx_cpymem(h->last, r->headers_out.content_type->value.data,
                             r->headers_out.content_type->value.len);

        if (r->headers_out.charset.len) {
            h->last = ngx_cpymem(h->last, "; charset=",
                                 sizeof("; charset=") - 1);
            h->last = ngx_cpymem(h->last, r->headers_out.charset.data,
                                 r->headers_out.charset.len);

            r->headers_out.content_type->value.len = h->last - p;
            r->headers_out.content_type->value.data = p;
        }

        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        p = h->last + sizeof("Location: ") - 1;
        h->last = ngx_cpymem(h->last, "Location: http://",
                             sizeof("Location: http://") - 1);
        h->last = ngx_cpymem(h->last, r->server_name->data,
                             r->server_name->len);
        if (r->port != 80) {
            h->last = ngx_cpymem(h->last, r->port_name->data,
                                 r->port_name->len);
        }

        h->last = ngx_cpymem(h->last, r->headers_out.location->value.data,
                             r->headers_out.location->value.len);

        r->headers_out.location->value.len = h->last - p;
        r->headers_out.location->value.data = p;

        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (!(r->headers_out.last_modified && r->headers_out.last_modified->key.len)
        && r->headers_out.last_modified_time != -1)
    {
        h->last = ngx_cpymem(h->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        h->last += ngx_http_time(h->last, r->headers_out.last_modified_time);

        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (r->chunked) {
        h->last = ngx_cpymem(h->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->keepalive) {
        h->last = ngx_cpymem(h->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

    } else {
        h->last = ngx_cpymem(h->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
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

    if (!(ln = ngx_alloc_chain_link(r->pool))) {
        return NGX_ERROR;
    }

    ln->hunk = h;
    ln->next = NULL;

    return ngx_http_write_filter(r, ln);
}


static int ngx_http_header_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_top_header_filter = ngx_http_header_filter;

    return NGX_OK;
}
