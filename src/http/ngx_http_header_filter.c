
#include <nginx.h>

#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_write_filter.h>


static int ngx_http_header_filter(ngx_http_request_t *r);


ngx_http_module_t  ngx_http_header_filter_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* init server config */
    NULL,                                  /* create location config */
    NULL,                                  /* merge location config */

    NULL,                                  /* translate handler */

    ngx_http_header_filter,                /* output header filter */
    NULL,                                  /* next output header filter */
    NULL,                                  /* output body filter */
    NULL                                   /* next output body filter */
};


ngx_module_t  ngx_http_header_filter_module = {
    0,                                     /* module index */
    &ngx_http_header_filter_module_ctx,    /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


static char server_string[] = "Server: " NGINX_VER CRLF;


static ngx_str_t http_codes[] = {

    ngx_string("200 OK"),
#if 0
    { 6,  "200 OK" },
#endif

    { 21, "301 Moved Permanently" },
    { 21, "302 Moved Temporarily" },
    { 0,  NULL },
    { 16, "304 Not Modified" },

    { 15, "400 Bad Request" },
    { 0,  NULL },
    { 0,  NULL },
    { 13, "403 Forbidden" },
    { 13, "404 Not Found" },

    { 25, "500 Internal Server Error" }
};



static int ngx_http_header_filter(ngx_http_request_t *r)
{
    int               len, status, i;
    time_t            ims;
    ngx_hunk_t       *h;
    ngx_chain_t      *ch;
    ngx_table_elt_t  *header;

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_OK;
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
            status = r->headers_out.status - NGX_HTTP_OK;

        } else if (r->headers_out.status < NGX_HTTP_BAD_REQUEST) {
            status = r->headers_out.status - NGX_HTTP_MOVED_PERMANENTLY + 1;
            r->header_only = 1;

        } else if (r->headers_out.status < NGX_HTTP_INTERNAL_SERVER_ERROR) {
            status = r->headers_out.status - NGX_HTTP_BAD_REQUEST + 1 + 4;

        } else {
            status = r->headers_out.status
                                 - NGX_HTTP_INTERNAL_SERVER_ERROR + 1 + 4 + 5;
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
        /* "Date: ... \r\n"; */
        len += 37;
    }

    /* 2^64 is 20 characters */
    if (r->headers_out.content_length >= 0) {
        len += 48;
    }

#if 0
    if (r->headers_out.content_type.len)
        len += r->headers_out.content_type.len + 16;
#endif

    if (r->headers_out.last_modified && r->headers_out.last_modified->key.len) {
        len += r->headers_out.last_modified->key.len
               + r->headers_out.last_modified->value.len + 2;
    } else if (r->headers_out.last_modified_time != -1) {
        /* "Last-Modified: ... \r\n"; */
        len += 46;
    }

    if (r->keepalive == 0) {
        len += 19;
    } else {
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
    ngx_memcpy(h->last.mem, "HTTP/1.1 ", 9);
    h->last.mem += 9;

    /* status line */
    if (r->headers_out.status_line.len) {
        ngx_memcpy(h->last.mem, r->headers_out.status_line.data,
                   r->headers_out.status_line.len);
        h->last.mem += r->headers_out.status_line.len;

    } else {
        ngx_memcpy(h->last.mem, http_codes[status].data,
                   http_codes[status].len);
        h->last.mem += http_codes[status].len;
    }
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    if (!(r->headers_out.server && r->headers_out.server->key.len)) {
        ngx_memcpy(h->last.mem, server_string, sizeof(server_string) - 1);
        h->last.mem += sizeof(server_string) - 1;
    }

    if (!(r->headers_out.date && r->headers_out.date->key.len)) {
        ngx_memcpy(h->last.mem, "Date: ", 6);
        h->last.mem += 6;
        h->last.mem += ngx_http_get_time(h->last.mem, time(NULL));
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }

    /* 2^64 is 20 characters  */
    if (r->headers_out.content_length >= 0) {
        h->last.mem += ngx_snprintf(h->last.mem, 49,
                                    "Content-Length: " OFF_FMT CRLF,
                                    r->headers_out.content_length);
    }

#if 0
    if (r->headers_out.content_type.len) {
        ngx_memcpy(h->last.mem, "Content-Type: ", 14);
        h->last.mem += 14;
        ngx_memcpy(h->last.mem, r->headers_out.content_type.data,
                   r->headers_out.content_type.len);
        h->last.mem += r->headers_out.content_type.len;
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }
#endif

    if (!(r->headers_out.last_modified
          && r->headers_out.last_modified->key.len)
        && r->headers_out.last_modified_time != -1)
    {
        ngx_memcpy(h->last.mem, "Last-Modified: ", 15);
        h->last.mem += 15;
        h->last.mem += ngx_http_get_time(h->last.mem,
                                         r->headers_out.last_modified_time);
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }

    if (r->keepalive == 0) {
        ngx_memcpy(h->last.mem, "Connection: close" CRLF, 19);
        h->last.mem += 19;

    } else {
        ngx_memcpy(h->last.mem, "Connection: keep-alive" CRLF, 24);
        h->last.mem += 24;
    }

    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0) {
            continue;
        }

        ngx_memcpy(h->last.mem, header[i].key.data, header[i].key.len);
        h->last.mem += header[i].key.len;
        *(h->last.mem++) = ':' ; *(h->last.mem++) = ' ' ;

        ngx_memcpy(h->last.mem, header[i].value.data, header[i].value.len);
        h->last.mem += header[i].value.len;
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }

    /* STUB */
    *(h->last.mem) = '\0';
    ngx_log_debug(r->connection->log, "%s\n" _ h->pos.mem);
    /**/

    /* end of HTTP header */
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    if (r->header_only) {
        h->type |= NGX_HUNK_LAST;
    }

    ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

    ch->hunk = h;
    ch->next = NULL;

    return ngx_http_write_filter(r, ch);
}
