
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
ngx_http_v3_parse_header(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                        n;
    u_char                       *p;
    ngx_int_t                     rc;
    ngx_str_t                    *name, *value;
    ngx_connection_t             *c;
    ngx_http_v3_parse_headers_t  *st;
    enum {
        sw_start = 0,
        sw_prev,
        sw_headers,
        sw_last,
        sw_done
    };

    c = r->connection;
    st = r->h3_parse;

    if (st == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header");

        st = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_parse_headers_t));
        if (st == NULL) {
            goto failed;
        }

        r->h3_parse = st;
    }

    switch (r->state) {

    case sw_prev:
        r->state = sw_headers;
        return NGX_OK;

    case sw_done:
        goto done;

    case sw_last:
        r->state = sw_done;
        return NGX_OK;

    default:
        break;
    }

    while (b->pos < b->last) {
        rc = ngx_http_v3_parse_headers(c, st, *b->pos++);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_AGAIN) {
            continue;
        }

        name = &st->header_rep.header.name;
        value = &st->header_rep.header.value;

        if (r->state == sw_start) {

            if (ngx_http_v3_process_pseudo_header(r, name, value) == NGX_OK) {
                if (rc == NGX_OK) {
                    continue;
                }

                r->state = sw_done;

            } else if (rc == NGX_OK) {
                r->state = sw_prev;

            } else {
                r->state = sw_last;
            }

            n = (r->method_end - r->method_start) + 1
                + (r->uri_end - r->uri_start) + 1
                + sizeof("HTTP/3") - 1;

            p = ngx_pnalloc(c->pool, n);
            if (p == NULL) {
                goto failed;
            }

            r->request_start = p;

            p = ngx_cpymem(p, r->method_start, r->method_end - r->method_start);
            *p++ = ' ';
            p = ngx_cpymem(p, r->uri_start, r->uri_end - r->uri_start);
            *p++ = ' ';
            p = ngx_cpymem(p, "HTTP/3", sizeof("HTTP/3") - 1);

            r->request_end = p;

        } else if (rc == NGX_DONE) {
            r->state = sw_done;
        }

        r->header_name_start = name->data;
        r->header_name_end = name->data + name->len;
        r->header_start = value->data;
        r->header_end = value->data + value->len;
        r->header_hash = ngx_hash_key(name->data, name->len);

        /* XXX r->lowcase_index = i; */

        return NGX_OK;
    }

    return NGX_AGAIN;

failed:

    return r->state == sw_start ? NGX_HTTP_PARSE_INVALID_REQUEST
                                : NGX_HTTP_PARSE_INVALID_HEADER;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header done");

    return NGX_HTTP_PARSE_HEADER_DONE;
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
        r->method_start = value->data;
        r->method_end = value->data + value->len;

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


ngx_chain_t *
ngx_http_v3_create_header(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     len, hlen, n;
    ngx_buf_t                 *b;
    ngx_uint_t                 i, j;
    ngx_chain_t               *hl, *cl, *bl;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 create header");

    /* XXX support chunked body in the chunked filter */
    if (r->headers_out.content_length_n == -1) {
        return NULL;
    }

    len = 0;

    if (r->headers_out.status == NGX_HTTP_OK) {
        len += ngx_http_v3_encode_prefix_int(NULL, 25, 6);

    } else {
        len += 3 + ngx_http_v3_encode_prefix_int(NULL, 25, 4)
                 + ngx_http_v3_encode_prefix_int(NULL, 3, 7);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            n = sizeof(NGINX_VER) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            n = sizeof(NGINX_VER_BUILD) - 1;

        } else {
            n = sizeof("nginx") - 1;
        }

        len += ngx_http_v3_encode_prefix_int(NULL, 92, 4)
               + ngx_http_v3_encode_prefix_int(NULL, n, 7) + n;
    }

    if (r->headers_out.date == NULL) {
        len += ngx_http_v3_encode_prefix_int(NULL, 6, 4)
               + ngx_http_v3_encode_prefix_int(NULL, ngx_cached_http_time.len,
                                               7)
               + ngx_cached_http_time.len;
    }

    if (r->headers_out.content_type.len) {
        n = r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        len += ngx_http_v3_encode_prefix_int(NULL, 53, 4)
               + ngx_http_v3_encode_prefix_int(NULL, n, 7) + n;
    }

    if (r->headers_out.content_length_n == 0) {
        len += ngx_http_v3_encode_prefix_int(NULL, 4, 6);

    } else {
        len += ngx_http_v3_encode_prefix_int(NULL, 4, 4) + 1 + NGX_OFF_T_LEN;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += ngx_http_v3_encode_prefix_int(NULL, 10, 4) + 1
               + sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT");
    }

    /* XXX location */

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            /* Vary: Accept-Encoding */
            len += ngx_http_v3_encode_prefix_int(NULL, 59, 6);

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

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

        if (header[i].hash == 0) {
            continue;
        }

        len += ngx_http_v3_encode_prefix_int(NULL, header[i].key.len, 3)
               + header[i].key.len
               + ngx_http_v3_encode_prefix_int(NULL, header[i].value.len, 7 )
               + header[i].value.len;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 header len:%uz", len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    *b->last++ = 0;
    *b->last++ = 0;

    if (r->headers_out.status == NGX_HTTP_OK) {
        /* :status: 200 */
        *b->last = 0xc0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 25, 6);

    } else {
        /* :status: 200 */
        *b->last = 0x70;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 25, 4);
        *b->last = 0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 3, 7);
        b->last = ngx_sprintf(b->last, "%03ui", r->headers_out.status);
    }

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            p = (u_char *) NGINX_VER;
            n = sizeof(NGINX_VER) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            p = (u_char *) NGINX_VER_BUILD;
            n = sizeof(NGINX_VER_BUILD) - 1;

        } else {
            p = (u_char *) "nginx";
            n = sizeof("nginx") - 1;
        }

        /* server */
        *b->last = 0x70;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 92, 4);
        *b->last = 0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, n, 7);
        b->last = ngx_cpymem(b->last, p, n);
    }

    if (r->headers_out.date == NULL) {
        /* date */
        *b->last = 0x70;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 6, 4);
        *b->last = 0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last,
                                                 ngx_cached_http_time.len, 7);
        b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
                             ngx_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        n = r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        /* content-type: text/plain */
        *b->last = 0x70;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 53, 4);
        *b->last = 0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, n, 7);

        p = b->last;
        b->last = ngx_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }
    }

    if (r->headers_out.content_length_n == 0) {
        /* content-length: 0 */
        *b->last = 0xc0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 4, 6);

    } else if (r->headers_out.content_length_n > 0) {
        /* content-length: 0 */
        *b->last = 0x70;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 4, 4);
        p = b->last++;
        b->last = ngx_sprintf(b->last, "%O", r->headers_out.content_length_n);
        *p = b->last - p - 1;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        /* last-modified */
        *b->last = 0x70;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 10, 4);
        p = b->last++;
        b->last = ngx_http_time(b->last, r->headers_out.last_modified_time);
        *p = b->last - p - 1;
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        /* vary: accept-encoding */
        *b->last = 0xc0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last, 59, 6);
    }
#endif

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

        if (header[i].hash == 0) {
            continue;
        }

        *b->last = 0x30;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last,
                                                           header[i].key.len,
                                                           3);
        for (j = 0; j < header[i].key.len; j++) {
            *b->last++ = ngx_tolower(header[i].key.data[j]);
        }

        *b->last = 0;
        b->last = (u_char *) ngx_http_v3_encode_prefix_int(b->last,
                                                           header[i].value.len,
                                                           7);
        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
    }

    cl = ngx_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    n = b->last - b->pos;

    len = 1 + ngx_http_v3_encode_varlen_int(NULL, n);

    b = ngx_create_temp_buf(c->pool, len);
    if (b == NULL) {
        return NULL;
    }

    *b->last++ = NGX_HTTP_V3_FRAME_HEADERS;
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    hl = ngx_alloc_chain_link(c->pool);
    if (hl == NULL) {
        return NULL;
    }

    hl->buf = b;
    hl->next = cl;

    hlen = 1 + ngx_http_v3_encode_varlen_int(NULL, len);

    if (r->headers_out.content_length_n >= 0) {
        len = 1 + ngx_http_v3_encode_varlen_int(NULL,
                                              r->headers_out.content_length_n);

        b = ngx_create_temp_buf(c->pool, len);
        if (b == NULL) {
            NULL;
        }

        *b->last++ = NGX_HTTP_V3_FRAME_DATA;
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                              r->headers_out.content_length_n);

        bl = ngx_alloc_chain_link(c->pool);
        if (bl == NULL) {
            return NULL;
        }

        bl->buf = b;
        bl->next = NULL;
        cl->next = bl;
    }

    return hl;
}
