
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_v3_process_pseudo_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);


struct {
    ngx_str_t   name;
    ngx_uint_t  method;
} ngx_http_v3_methods[] = {

    { ngx_string("GET"),       NGX_HTTP_GET },
    { ngx_string("POST"),      NGX_HTTP_POST },
    { ngx_string("HEAD"),      NGX_HTTP_HEAD },
    { ngx_string("OPTIONS"),   NGX_HTTP_OPTIONS },
    { ngx_string("PROPFIND"),  NGX_HTTP_PROPFIND },
    { ngx_string("PUT"),       NGX_HTTP_PUT },
    { ngx_string("MKCOL"),     NGX_HTTP_MKCOL },
    { ngx_string("DELETE"),    NGX_HTTP_DELETE },
    { ngx_string("COPY"),      NGX_HTTP_COPY },
    { ngx_string("MOVE"),      NGX_HTTP_MOVE },
    { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
    { ngx_string("LOCK"),      NGX_HTTP_LOCK },
    { ngx_string("UNLOCK"),    NGX_HTTP_UNLOCK },
    { ngx_string("PATCH"),     NGX_HTTP_PATCH },
    { ngx_string("TRACE"),     NGX_HTTP_TRACE }
};


ngx_int_t
ngx_http_v3_parse_request(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                        len;
    u_char                       *p;
    ngx_int_t                     rc, n;
    ngx_str_t                    *name, *value;
    ngx_connection_t             *c;
    ngx_http_v3_parse_headers_t  *st;

    c = r->connection;
    st = r->h3_parse;

    if (st == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header");

        st = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_parse_headers_t));
        if (st == NULL) {
            goto failed;
        }

        r->h3_parse = st;
        r->parse_start = b->pos;
        r->state = 1;
    }

    while (b->pos < b->last) {
        rc = ngx_http_v3_parse_headers(c, st, *b->pos);

        if (rc > 0) {
            ngx_http_v3_finalize_connection(c, rc,
                                            "could not parse request headers");
            goto failed;
        }

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_BUSY) {
            return NGX_BUSY;
        }

        b->pos++;

        if (rc == NGX_AGAIN) {
            continue;
        }

        name = &st->header_rep.header.name;
        value = &st->header_rep.header.value;

        n = ngx_http_v3_process_pseudo_header(r, name, value);

        if (n == NGX_ERROR) {
            goto failed;
        }

        if (n == NGX_OK && rc == NGX_OK) {
            continue;
        }

        len = r->method_name.len + 1
            + (r->uri_end - r->uri_start) + 1
            + sizeof("HTTP/3.0") - 1;

        p = ngx_pnalloc(c->pool, len);
        if (p == NULL) {
            goto failed;
        }

        r->request_start = p;

        p = ngx_cpymem(p, r->method_name.data, r->method_name.len);
        r->method_end = p - 1;
        *p++ = ' ';
        p = ngx_cpymem(p, r->uri_start, r->uri_end - r->uri_start);
        *p++ = ' ';
        r->http_protocol.data = p;
        p = ngx_cpymem(p, "HTTP/3.0", sizeof("HTTP/3.0") - 1);

        r->request_end = p;
        r->state = 0;

        return NGX_OK;
    }

    return NGX_AGAIN;

failed:

    return NGX_HTTP_PARSE_INVALID_REQUEST;
}


ngx_int_t
ngx_http_v3_parse_header(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t allow_underscores)
{
    u_char                        ch;
    ngx_int_t                     rc;
    ngx_str_t                    *name, *value;
    ngx_uint_t                    hash, i, n;
    ngx_connection_t             *c;
    ngx_http_v3_parse_headers_t  *st;
    enum {
        sw_start = 0,
        sw_done,
        sw_next,
        sw_header
    };

    c = r->connection;
    st = r->h3_parse;

    switch (r->state) {

    case sw_start:
        r->parse_start = b->pos;

        if (st->state) {
            r->state = sw_next;
            goto done;
        }

        name = &st->header_rep.header.name;

        if (name->len && name->data[0] != ':') {
            r->state = sw_done;
            goto done;
        }

        /* fall through */

    case sw_done:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse header done");
        return NGX_HTTP_PARSE_HEADER_DONE;

    case sw_next:
        r->parse_start = b->pos;
        r->invalid_header = 0;
        break;

    case sw_header:
        break;
    }

    while (b->pos < b->last) {
        rc = ngx_http_v3_parse_headers(c, st, *b->pos++);

        if (rc > 0) {
            ngx_http_v3_finalize_connection(c, rc,
                                            "could not parse request headers");
            return NGX_HTTP_PARSE_INVALID_HEADER;
        }

        if (rc == NGX_ERROR) {
            return NGX_HTTP_PARSE_INVALID_HEADER;
        }

        if (rc == NGX_DONE) {
            r->state = sw_done;
            goto done;
        }

        if (rc == NGX_OK) {
            r->state = sw_next;
            goto done;
        }
    }

    r->state = sw_header;
    return NGX_AGAIN;

done:

    name = &st->header_rep.header.name;
    value = &st->header_rep.header.value;

    r->header_name_start = name->data;
    r->header_name_end = name->data + name->len;
    r->header_start = value->data;
    r->header_end = value->data + value->len;

    hash = 0;
    i = 0;

    for (n = 0; n < name->len; n++) {
        ch = name->data[n];

        if (ch >= 'A' && ch <= 'Z') {
            /*
             * A request or response containing uppercase
             * header field names MUST be treated as malformed
             */
            return NGX_HTTP_PARSE_INVALID_HEADER;
        }

        if (ch == '\0') {
            return NGX_HTTP_PARSE_INVALID_HEADER;
        }

        if (ch == '_' && !allow_underscores) {
            r->invalid_header = 1;
            continue;
        }

        if ((ch < 'a' || ch > 'z')
            && (ch < '0' || ch > '9')
            && ch != '-' && ch != '_')
        {
            r->invalid_header = 1;
            continue;
        }

        hash = ngx_hash(hash, ch);
        r->lowcase_header[i++] = ch;
        i &= (NGX_HTTP_LC_HEADER_LEN - 1);
    }

    r->header_hash = hash;
    r->lowcase_index = i;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_process_pseudo_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

    if (name->len == 0 || name->data[0] != ':') {
        return NGX_DONE;
    }

    c = r->connection;

    if (name->len == 7 && ngx_strncmp(name->data, ":method", 7) == 0) {
        r->method_name = *value;

        for (i = 0; i < sizeof(ngx_http_v3_methods)
                        / sizeof(ngx_http_v3_methods[0]); i++)
        {
            if (value->len == ngx_http_v3_methods[i].name.len
                && ngx_strncmp(value->data, ngx_http_v3_methods[i].name.data,
                               value->len) == 0)
            {
                r->method = ngx_http_v3_methods[i].method;
                break;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 method \"%V\" %ui", value, r->method);
        return NGX_OK;
    }

    if (name->len == 5 && ngx_strncmp(name->data, ":path", 5) == 0) {
        r->uri_start = value->data;
        r->uri_end = value->data + value->len;

        if (ngx_http_parse_uri(r) != NGX_OK) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent invalid :path header: \"%V\"", value);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 path \"%V\"", value);

        return NGX_OK;
    }

    if (name->len == 7 && ngx_strncmp(name->data, ":scheme", 7) == 0) {
        r->schema_start = value->data;
        r->schema_end = value->data + value->len;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 schema \"%V\"", value);

        return NGX_OK;
    }

    if (name->len == 10 && ngx_strncmp(name->data, ":authority", 10) == 0) {
        r->host_start = value->data;
        r->host_end = value->data + value->len;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 authority \"%V\"", value);

        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 unknown pseudo header \"%V\" \"%V\"", name, value);

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_parse_request_body(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_chunked_t *ctx)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_v3_parse_data_t  *st;
    enum {
        sw_start = 0,
        sw_skip
    };

    c = r->connection;
    st = ctx->h3_parse;

    if (st == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse request body");

        st = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_parse_data_t));
        if (st == NULL) {
            goto failed;
        }

        ctx->h3_parse = st;
    }

    while (b->pos < b->last && ctx->size == 0) {

        rc = ngx_http_v3_parse_data(c, st, *b->pos++);

        if (rc > 0) {
            ngx_http_v3_finalize_connection(c, rc,
                                            "could not parse request body");
            goto failed;
        }

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_AGAIN) {
            ctx->state = sw_skip;
            continue;
        }

        if (rc == NGX_DONE) {
            return NGX_DONE;
        }

        /* rc == NGX_OK */

        ctx->size = st->length;
        ctx->state = sw_start;
    }

    if (ctx->state == sw_skip) {
        ctx->length = 1;
        return NGX_AGAIN;
    }

    if (b->pos == b->last) {
        ctx->length = ctx->size;
        return NGX_AGAIN;
    }

    return NGX_OK;

failed:

    return NGX_ERROR;
}
