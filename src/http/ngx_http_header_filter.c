
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static ngx_int_t ngx_http_header_filter_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_header_filter(ngx_http_request_t *r);


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
                       * because we treat such requests as the HTTP/0.9
                       * requests and send only a body without a header
                       */
    ngx_null_string,  /* "415 Unsupported Media Type" */
    ngx_string("416 Requested Range Not Satisfiable"),

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Method Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out")
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
    { ngx_string("Expires"), offsetof(ngx_http_headers_out_t, expires) },
    { ngx_string("Cache-Control"),
                            offsetof(ngx_http_headers_out_t, cache_control) },
    { ngx_string("ETag"), offsetof(ngx_http_headers_out_t, etag) },

    { ngx_null_string, 0 }
};


static ngx_int_t ngx_http_header_filter(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    ngx_uint_t                 status, i;
    ngx_buf_t                 *b;
    ngx_chain_t               *ln;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_OK;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
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
            len += r->port_text->len;
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

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;

        /*
         * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
         * MSIE keeps the connection alive for about 60-65 seconds.
         * Opera keeps the connection alive very long.
         * Mozilla keeps the connection alive for N plus about 1-10 seconds.
         * Konqueror keeps the connection alive for about N seconds.
         */

        if (clcf->keepalive_header
            && (r->headers_in.gecko || r->headers_in.konqueror))
        {
            len += sizeof("Keep-Alive: timeout=") - 1 + TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: closed" CRLF) - 1;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == 0) {
            continue;
        }

        /* 2 is for ": " and 2 is for "\r\n" */
        len += header[i].key.len + 2 + header[i].value.len + 2;
    }

    if (!(b = ngx_create_temp_buf(r->pool, len))) {
        return NGX_ERROR;
    }

    /* "HTTP/1.x " */
    b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (r->headers_out.status_line.len) {
        b->last = ngx_cpymem(b->last, r->headers_out.status_line.data,
                             r->headers_out.status_line.len);

    } else {
        b->last = ngx_cpymem(b->last, http_codes[status].data,
                             http_codes[status].len);
    }
    *(b->last++) = CR; *(b->last++) = LF;

    if (!(r->headers_out.server && r->headers_out.server->key.len)) {
        b->last = ngx_cpymem(b->last, server_string, sizeof(server_string) - 1);
    }

    if (!(r->headers_out.date && r->headers_out.date->key.len)) {
        b->last = ngx_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
                             ngx_cached_http_time.len);

        *(b->last++) = CR; *(b->last++) = LF;
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n >= 0) {
            b->last += ngx_snprintf((char *) b->last,
                                sizeof("Content-Length: ") + NGX_OFF_T_LEN + 2,
                                "Content-Length: " OFF_T_FMT CRLF,
                                r->headers_out.content_length_n);
        }
    }

    if (r->headers_out.content_type && r->headers_out.content_type->value.len) {
        b->last = ngx_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = ngx_cpymem(b->last, r->headers_out.content_type->value.data,
                             r->headers_out.content_type->value.len);

        if (r->headers_out.charset.len) {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_cpymem(b->last, r->headers_out.charset.data,
                                 r->headers_out.charset.len);

            r->headers_out.content_type->value.len = b->last - p;
            r->headers_out.content_type->value.data = p;
        }

        *(b->last++) = CR; *(b->last++) = LF;
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        p = b->last + sizeof("Location: ") - 1;
        b->last = ngx_cpymem(b->last, "Location: http://",
                             sizeof("Location: http://") - 1);
        b->last = ngx_cpymem(b->last, r->server_name->data,
                             r->server_name->len);
        if (r->port != 80) {
            b->last = ngx_cpymem(b->last, r->port_text->data,
                                 r->port_text->len);
        }

        b->last = ngx_cpymem(b->last, r->headers_out.location->value.data,
                             r->headers_out.location->value.len);

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;

        *(b->last++) = CR; *(b->last++) = LF;
    }

    if (!(r->headers_out.last_modified && r->headers_out.last_modified->key.len)
        && r->headers_out.last_modified_time != -1)
    {
        b->last = ngx_cpymem(b->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        b->last += ngx_http_time(b->last, r->headers_out.last_modified_time);

        *(b->last++) = CR; *(b->last++) = LF;
    }

    if (r->chunked) {
        b->last = ngx_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->keepalive) {
        b->last = ngx_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header
            && (r->headers_in.gecko || r->headers_in.konqueror))
        {
            b->last += ngx_snprintf((char *) b->last,
                            sizeof("Keep-Alive: timeout=") + TIME_T_LEN + 2,
                            "Keep-Alive: timeout=" TIME_T_FMT CRLF,
                            clcf->keepalive_header);
        }

    } else {
        b->last = ngx_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == 0) {
            continue;
        }

        b->last = ngx_cpymem(b->last, header[i].key.data, header[i].key.len);
        *(b->last++) = ':' ; *(b->last++) = ' ' ;

        b->last = ngx_cpymem(b->last, header[i].value.data,
                             header[i].value.len);
        *(b->last++) = CR; *(b->last++) = LF;
    }

#if (NGX_DEBUG)
    *(b->last) = '\0';
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s\n", b->pos);
#endif

    /* the end of HTTP header */
    *(b->last++) = CR; *(b->last++) = LF;

    r->header_size = b->last - b->pos;

    if (r->header_only) {
        b->last_buf = 1;
    }

    if (!(ln = ngx_alloc_chain_link(r->pool))) {
        return NGX_ERROR;
    }

    ln->buf = b;
    ln->next = NULL;

    return ngx_http_write_filter(r, ln);
}


static ngx_int_t ngx_http_header_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_top_header_filter = ngx_http_header_filter;

    return NGX_OK;
}
