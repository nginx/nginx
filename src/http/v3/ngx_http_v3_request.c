
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_V3_FRAME_DATA          0x00
#define NGX_HTTP_V3_FRAME_HEADERS       0x01
#define NGX_HTTP_V3_FRAME_CANCEL_PUSH   0x03
#define NGX_HTTP_V3_FRAME_SETTINGS      0x04
#define NGX_HTTP_V3_FRAME_PUSH_PROMISE  0x05
#define NGX_HTTP_V3_FRAME_GOAWAY        0x07
#define NGX_HTTP_V3_FRAME_MAX_PUSH_ID   0x0d


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
ngx_http_v3_parse_header(ngx_http_request_t *r, ngx_buf_t *b, ngx_uint_t pseudo)
{
    u_char                *p, ch;
    ngx_str_t              name, value;
    ngx_int_t              rc;
    ngx_uint_t             length, index, insert_count, sign, base, delta_base,
                           huffman, dynamic, offset;
    ngx_connection_t      *c;
    ngx_http_v3_header_t  *h;
    enum {
        sw_start = 0,
        sw_length,
        sw_length_1,
        sw_length_2,
        sw_length_3,
        sw_header_block,
        sw_req_insert_count,
        sw_delta_base,
        sw_read_delta_base,
        sw_header,
        sw_old_header,
        sw_header_ri,
        sw_header_pbi,
        sw_header_lri,
        sw_header_lpbi,
        sw_header_l_name_len,
        sw_header_l_name,
        sw_header_value_len,
        sw_header_read_value_len,
        sw_header_value
    } state;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header, pseudo:%ui", pseudo);

    if (r->state == sw_old_header) {
        r->state = sw_header;
        return NGX_OK;
    }

    length = r->h3_length;
    index = r->h3_index;
    insert_count = r->h3_insert_count;
    sign = r->h3_sign;
    delta_base = r->h3_delta_base;
    huffman = r->h3_huffman;
    dynamic = r->h3_dynamic;
    offset = r->h3_offset;

    name.data = r->header_name_start;
    name.len = r->header_name_end - r->header_name_start;
    value.data = r->header_start;
    value.len = r->header_end - r->header_start;

    if (r->state == sw_start) {
        length = 1;
    }

again:

    state = r->state;

    if (state == sw_header && length == 0) {
        r->state = sw_start;
        return NGX_HTTP_PARSE_HEADER_DONE;
    }

    for (p = b->pos; p < b->last; p++) {

        if (state >= sw_header_block && length-- == 0) {
            goto failed;
        }

        ch = *p;

        switch (state) {

        case sw_start:

            if (ch != NGX_HTTP_V3_FRAME_HEADERS) {
                goto failed;
            }

            r->request_start = p;
            state = sw_length;
            break;

        case sw_length:

            length = ch;
            if (length & 0xc0) {
                state = sw_length_1;
                break;
            }

            state = sw_header_block;
            break;

        case sw_length_1:

            length = (length << 8) + ch;
            if ((length & 0xc000) != 0x4000) {
                state = sw_length_2;
                break;
            }

            length &= 0x3fff;
            state = sw_header_block;
            break;

        case sw_length_2:

            length = (length << 8) + ch;
            if ((length & 0xc00000) != 0x800000) {
                state = sw_length_3;
                break;
            }

            /* fall through */

        case sw_length_3:

            length &= 0x3fffff;
            state = sw_header_block;
            break;

        case sw_header_block:

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 header block length:%ui", length);

            if (ch != 0xff) {
                insert_count = ch;
                state = sw_delta_base;
                break;
            }

            insert_count = 0;
            state = sw_req_insert_count;
            break;

        case sw_req_insert_count:

            insert_count = (insert_count << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            insert_count += 0xff;
            state = sw_delta_base;
            break;

        case sw_delta_base:

            sign = (ch & 0x80) ? 1 : 0;
            delta_base = ch & 0x7f;

            if (delta_base != 0x7f) {
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "http3 header block "
                               "insert_count:%ui, sign:%ui, delta_base:%ui",
                               insert_count, sign, delta_base);
                goto done;
            }

            delta_base = 0;
            state = sw_read_delta_base;
            break;

        case sw_read_delta_base:

            delta_base = (delta_base << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            delta_base += 0x7f;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 header block "
                           "insert_count:%ui, sign:%ui, delta_base:%ui",
                           insert_count, sign, delta_base);
            goto done;

        case sw_header:

            index = 0;
            huffman = 0;
            ngx_str_null(&name);
            ngx_str_null(&value);

            if (ch & 0x80) {
                /* Indexed Header Field */

                dynamic = (ch & 0x40) ? 0 : 1;
                index = ch & 0x3f;

                if (index != 0x3f) {
                    goto done;
                }

                index = 0;
                state = sw_header_ri;
                break;
            }

            if (ch & 0x40) {
                /* Literal Header Field With Name Reference */

                dynamic = (ch & 0x10) ? 0 : 1;
                index = ch & 0x0f;

                if (index != 0x0f) {
                    state = sw_header_value_len;
                    break;
                }

                index = 0;
                state = sw_header_lri;
                break;
            }

            if (ch & 0x20) {
                /* Literal Header Field Without Name Reference */

                huffman = (ch & 0x08) ? 1 : 0;
                name.len = ch & 0x07;

                if (name.len == 0) {
                    goto failed;
                }

                if (name.len != 0x07) {
                    offset = 0;
                    state = sw_header_l_name;
                    break;
                }

                name.len = 0;
                state = sw_header_l_name_len;
                break;
            }

            if (ch & 10) {
                /* Indexed Header Field With Post-Base Index */

                dynamic = 2;
                index = ch & 0x0f;

                if (index != 0x0f) {
                    goto done;
                }

                index = 0;
                state = sw_header_pbi;
                break;
            }

            /* Literal Header Field With Post-Base Name Reference */

            dynamic = 2;
            index = ch & 0x07;

            if (index != 0x07) {
                state = sw_header_value_len;
                break;
            }

            index = 0;
            state = sw_header_lpbi;
            break;

        case sw_header_ri:

            index = (index << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            index += 0x3f;
            goto done;

        case sw_header_pbi:

            index = (index << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            index += 0x0f;
            goto done;

        case sw_header_lri:

            index = (index << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            index += 0x0f;
            state = sw_header_value_len;
            break;

        case sw_header_lpbi:

            index = (index << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            index += 0x07;
            state = sw_header_value_len;
            break;


        case sw_header_l_name_len:

            name.len = (name.len << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            name.len += 0x07;
            offset = 0;
            state = sw_header_l_name;
            break;

        case sw_header_l_name:
            if (offset++ == 0) {
                name.data = p;
            }

            if (offset != name.len) {
                break;
            }

            if (huffman) {
                if (ngx_http_v3_decode_huffman(c, &name) != NGX_OK) {
                    goto failed;
                }
            }

            state = sw_header_value_len;
            break;

        case sw_header_value_len:

            huffman = (ch & 0x80) ? 1 : 0;
            value.len = ch & 0x7f;

            if (value.len == 0) {
                value.data = p;
                goto done;
            }

            if (value.len != 0x7f) {
                offset = 0;
                state = sw_header_value;
                break;
            }

            value.len = 0;
            state = sw_header_read_value_len;
            break;

        case sw_header_read_value_len:

            value.len = (value.len << 7) + (ch & 0x7f);
            if (ch & 0x80) {
                break;
            }

            value.len += 0x7f;
            offset = 0;
            state = sw_header_value;
            break;

        case sw_header_value:

            if (offset++ == 0) {
                value.data = p;
            }

            if (offset != value.len) {
                break;
            }

            if (huffman) {
                if (ngx_http_v3_decode_huffman(c, &value) != NGX_OK) {
                    goto failed;
                }
            }

            goto done;

        case sw_old_header:

            break;
        }
    }

    b->pos = p;
    r->state = state;
    r->h3_length = length;
    r->h3_index = index;
    r->h3_insert_count = insert_count;
    r->h3_sign = sign;
    r->h3_delta_base = delta_base;
    r->h3_huffman = huffman;
    r->h3_dynamic = dynamic;
    r->h3_offset = offset;

    /* XXX fix large reallocations */
    r->header_name_start = name.data;
    r->header_name_end = name.data + name.len;
    r->header_start = value.data;
    r->header_end = value.data + value.len;

    /* XXX r->lowcase_index = i; */

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    r->state = sw_header;
    r->h3_length = length;
    r->h3_insert_count = insert_count;
    r->h3_sign = sign;
    r->h3_delta_base = delta_base;

    if (state < sw_header) {
        if (ngx_http_v3_check_insert_count(c, insert_count) != NGX_OK) {
            return NGX_DONE;
        }

        goto again;
    }

    if (sign == 0) {
        base = insert_count + delta_base;
    } else {
        base = insert_count - delta_base - 1;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 header %s[%ui], base:%ui, \"%V\":\"%V\"",
                   dynamic ? "dynamic" : "static", index, base, &name, &value);

    if (name.data == NULL) {

        if (dynamic == 2) {
            index = base - index - 1;
        } else if (dynamic == 1) {
            index += base;
        }

        h = ngx_http_v3_lookup_table(c, dynamic, index);
        if (h == NULL) {
            goto failed;
        }

        name = h->name;

        if (value.data == NULL) {
            value = h->value;
        }
    }

    /* XXX ugly reallocation for the trailing '\0' */

    p = ngx_pnalloc(c->pool, name.len + value.len + 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, name.data, name.len);
    name.data = p;
    ngx_memcpy(p + name.len + 1, value.data, value.len);
    value.data = p + name.len + 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 header \"%V\":\"%V\"", &name, &value);

    if (pseudo) {
        rc = ngx_http_v3_process_pseudo_header(r, &name, &value);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_OK) {
            r->request_end = p + 1;
            goto again;
        }

        /* rc == NGX_DONE */

        r->state = sw_old_header;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 header left:%ui", length);

    r->header_name_start = name.data;
    r->header_name_end = name.data + name.len;
    r->header_start = value.data;
    r->header_end = value.data + value.len;
    r->header_hash = ngx_hash_key(name.data, name.len); /* XXX */

    /* XXX r->lowcase_index = i; */

    return NGX_OK;

failed:

    return NGX_HTTP_PARSE_INVALID_REQUEST;
}


static ngx_int_t
ngx_http_v3_process_pseudo_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

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

    if (name->len && name->data[0] == ':') {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 unknown pseudo header \"%V\" \"%V\"",
                       name, value);
        return NGX_OK;
    }

    return NGX_DONE;
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
        b->last = ngx_sprintf(b->last, "%03ui ", r->headers_out.status);
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
