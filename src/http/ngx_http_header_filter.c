
#include <nginx.h>

#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_write_filter.h>


static void ngx_http_header_filter_init(ngx_pool_t *pool,
                                        ngx_http_conf_filter_t *cf);
static int ngx_http_header_filter(ngx_http_request_t *r);


ngx_http_module_t  ngx_http_header_filter_module_ctx = {
    NULL,                                  /* create server config */
    NULL,                                  /* init server config */

    NULL,                                  /* create location config */
    NULL,                                  /* merge location config */

    ngx_http_header_filter_init            /* init filters */
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

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_null_string,  /* 303 */
    ngx_string("304 Not Modified"),

    ngx_string("400 Bad Request"),
    ngx_null_string,  /* 401 */
    ngx_null_string,  /* 402 */
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_null_string,  /* 405 */
    ngx_null_string,  /* 406 */
    ngx_null_string,  /* 407 */
    ngx_string("408 Request Time-out"),
    ngx_null_string,  /* 409 */
    ngx_null_string,  /* 410 */
    ngx_string("411 Length Required"),
    ngx_null_string,  /* 412 */
    ngx_string("413 Request Entity Too Large"),
    ngx_null_string,  /* "414 Request-URI Too Large" but we never send it
                         because we treat such requests as HTTP/0.9 requests
                         and send only the body without the header */
    ngx_null_string,  /* 415 */
    ngx_string("416 Requested Range Not Satisfiable"),

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Method Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out")
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
                                 - NGX_HTTP_INTERNAL_SERVER_ERROR + 1 + 4 + 17;
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
    ngx_memcpy(h->last, "HTTP/1.1 ", 9);
    h->last += 9;

    /* status line */
    if (r->headers_out.status_line.len) {
        ngx_memcpy(h->last, r->headers_out.status_line.data,
                   r->headers_out.status_line.len);
        h->last += r->headers_out.status_line.len;

    } else {
        ngx_memcpy(h->last, http_codes[status].data,
                   http_codes[status].len);
        h->last += http_codes[status].len;
    }
    *(h->last++) = CR; *(h->last++) = LF;

    if (!(r->headers_out.server && r->headers_out.server->key.len)) {
        ngx_memcpy(h->last, server_string, sizeof(server_string) - 1);
        h->last += sizeof(server_string) - 1;
    }

    if (!(r->headers_out.date && r->headers_out.date->key.len)) {
        ngx_memcpy(h->last, "Date: ", 6);
        h->last += 6;
        h->last += ngx_http_get_time(h->last, time(NULL));
        *(h->last++) = CR; *(h->last++) = LF;
    }

    /* 2^64 is 20 characters  */
    if (r->headers_out.content_length >= 0) {
        h->last += ngx_snprintf(h->last, 49,
                                    "Content-Length: " OFF_FMT CRLF,
                                    r->headers_out.content_length);
    }

#if 0
    if (r->headers_out.content_type.len) {
        ngx_memcpy(h->last, "Content-Type: ", 14);
        h->last += 14;
        ngx_memcpy(h->last, r->headers_out.content_type.data,
                   r->headers_out.content_type.len);
        h->last += r->headers_out.content_type.len;
        *(h->last++) = CR; *(h->last++) = LF;
    }
#endif

    if (!(r->headers_out.last_modified
          && r->headers_out.last_modified->key.len)
        && r->headers_out.last_modified_time != -1)
    {
        ngx_memcpy(h->last, "Last-Modified: ", 15);
        h->last += 15;
        h->last += ngx_http_get_time(h->last,
                                         r->headers_out.last_modified_time);
        *(h->last++) = CR; *(h->last++) = LF;
    }

    if (r->keepalive == 0) {
        ngx_memcpy(h->last, "Connection: close" CRLF, 19);
        h->last += 19;

    } else {
        ngx_memcpy(h->last, "Connection: keep-alive" CRLF, 24);
        h->last += 24;
    }

    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0) {
            continue;
        }

        ngx_memcpy(h->last, header[i].key.data, header[i].key.len);
        h->last += header[i].key.len;
        *(h->last++) = ':' ; *(h->last++) = ' ' ;

        ngx_memcpy(h->last, header[i].value.data, header[i].value.len);
        h->last += header[i].value.len;
        *(h->last++) = CR; *(h->last++) = LF;
    }

    /* STUB */
    *(h->last) = '\0';
    ngx_log_debug(r->connection->log, "%s\n" _ h->pos);
    /**/

    /* end of HTTP header */
    *(h->last++) = CR; *(h->last++) = LF;

    if (r->header_only) {
        h->type |= NGX_HUNK_LAST;
    }

    ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

    ch->hunk = h;
    ch->next = NULL;

    return ngx_http_write_filter(r, ch);
}


static void ngx_http_header_filter_init(ngx_pool_t *pool,
                                        ngx_http_conf_filter_t *cf)
{
    cf->output_header_filter = ngx_http_header_filter;
}
