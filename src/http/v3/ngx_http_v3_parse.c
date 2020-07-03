
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_v3_parse_lookup(ngx_connection_t *c,
    ngx_uint_t dynamic, ngx_uint_t index, ngx_str_t *name, ngx_str_t *value);


ngx_int_t
ngx_http_v3_parse_varlen_int(ngx_connection_t *c,
    ngx_http_v3_parse_varlen_int_t *st, u_char ch)
{
    enum {
        sw_start = 0,
        sw_length_2,
        sw_length_3,
        sw_length_4,
        sw_length_5,
        sw_length_6,
        sw_length_7,
        sw_length_8
    };

    switch (st->state) {

    case sw_start:

        st->value = ch;
        if (st->value & 0xc0) {
            st->state = sw_length_2;
            break;
        }

        goto done;

    case sw_length_2:

        st->value = (st->value << 8) + ch;
        if ((st->value & 0xc000) == 0x4000) {
            st->value &= 0x3fff;
            goto done;
        }

        st->state = sw_length_3;
        break;

    case sw_length_4:

        st->value = (st->value << 8) + ch;
        if ((st->value & 0xc0000000) == 0x80000000) {
            st->value &= 0x3fffffff;
            goto done;
        }

        st->state = sw_length_5;
        break;

    case sw_length_3:
    case sw_length_5:
    case sw_length_6:
    case sw_length_7:

        st->value = (st->value << 8) + ch;
        st->state++;
        break;

    case sw_length_8:

        st->value = (st->value << 8) + ch;
        st->value &= 0x3fffffffffffffff;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse varlen int %uL", st->value);

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_prefix_int(ngx_connection_t *c,
    ngx_http_v3_parse_prefix_int_t *st, ngx_uint_t prefix, u_char ch)
{
    ngx_uint_t  mask;
    enum {
        sw_start = 0,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        mask = (1 << prefix) - 1;
        st->value = ch & mask;

        if (st->value != mask) {
            goto done;
        }

        st->shift = 0;
        st->state = sw_value;
        break;

    case sw_value:

        st->value += (uint64_t) (ch & 0x7f) << st->shift;

        if (st->shift == 56
            && ((ch & 0x80) || (st->value & 0xc000000000000000)))
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client exceeded integer size limit");
            return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD;
        }

        if (ch & 0x80) {
            st->shift += 7;
            break;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse prefix int %uL", st->value);

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_headers(ngx_connection_t *c, ngx_http_v3_parse_headers_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_length,
        sw_prefix,
        sw_verify,
        sw_header_rep,
        sw_done
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse headers");

        if (ch != NGX_HTTP_V3_FRAME_HEADERS) {
            return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED;
        }

        st->state = sw_length;
        break;

    case sw_length:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        st->length = st->vlint.value;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse headers len:%ui", st->length);

        st->state = sw_prefix;
        break;

    case sw_prefix:

        if (st->length-- == 0) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        rc = ngx_http_v3_parse_header_block_prefix(c, &st->prefix, ch);

        if (rc == NGX_AGAIN) {
            break;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        if (st->length == 0) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        st->state = sw_verify;
        break;

    case sw_verify:

        rc = ngx_http_v3_check_insert_count(c, st->prefix.insert_count);
        if (rc != NGX_OK) {
            return rc;
        }

        st->state = sw_header_rep;

        /* fall through */

    case sw_header_rep:

        rc = ngx_http_v3_parse_header_rep(c, &st->header_rep, st->prefix.base,
                                          ch);
        st->length--;

        if (rc == NGX_AGAIN) {
            if (st->length == 0) {
                return NGX_HTTP_V3_ERR_FRAME_ERROR;
            }

            break;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        if (st->length == 0) {
            goto done;
        }

        return NGX_OK;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse headers done");

    if (st->prefix.insert_count > 0) {
        if (ngx_http_v3_client_ack_header(c, c->qs->id) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_block_prefix(ngx_connection_t *c,
    ngx_http_v3_parse_header_block_prefix_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_req_insert_count,
        sw_delta_base,
        sw_read_delta_base
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse header block prefix");

        st->state = sw_req_insert_count;

        /* fall through */

    case sw_req_insert_count:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 8, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->insert_count = st->pint.value;
        st->state = sw_delta_base;
        break;

    case sw_delta_base:

        st->sign = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_delta_base;

        /* fall through */

    case sw_read_delta_base:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->delta_base = st->pint.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    rc = ngx_http_v3_decode_insert_count(c, &st->insert_count);
    if (rc != NGX_OK) {
        return rc;
    }

    if (st->sign) {
        st->base = st->insert_count - st->delta_base - 1;
    } else {
        st->base = st->insert_count + st->delta_base;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                  "http3 parse header block prefix done "
                  "insert_count:%ui, sign:%ui, delta_base:%ui, base:%uL",
                  st->insert_count, st->sign, st->delta_base, st->base);

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_rep(ngx_connection_t *c,
    ngx_http_v3_parse_header_rep_t *st, ngx_uint_t base, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_header_ri,
        sw_header_lri,
        sw_header_l,
        sw_header_pbi,
        sw_header_lpbi
    };

    if (st->state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse header representation");

        ngx_memzero(&st->header, sizeof(ngx_http_v3_parse_header_t));

        st->header.base = base;

        if (ch & 0x80) {
            /* Indexed Header Field */

            st->state = sw_header_ri;

        } else if (ch & 0x40) {
            /* Literal Header Field With Name Reference */

            st->state = sw_header_lri;

        } else if (ch & 0x20) {
            /* Literal Header Field Without Name Reference */

            st->state = sw_header_l;

        } else if (ch & 0x10) {
            /* Indexed Header Field With Post-Base Index */

            st->state = sw_header_pbi;

        } else {
            /* Literal Header Field With Post-Base Name Reference */

            st->state = sw_header_lpbi;
        }
    }

    switch (st->state) {

    case sw_header_ri:
        rc = ngx_http_v3_parse_header_ri(c, &st->header, ch);
        break;

    case sw_header_lri:
        rc = ngx_http_v3_parse_header_lri(c, &st->header, ch);
        break;

    case sw_header_l:
        rc = ngx_http_v3_parse_header_l(c, &st->header, ch);
        break;

    case sw_header_pbi:
        rc = ngx_http_v3_parse_header_pbi(c, &st->header, ch);
        break;

    case sw_header_lpbi:
        rc = ngx_http_v3_parse_header_lpbi(c, &st->header, ch);
        break;

    default:
        rc = NGX_OK;
    }

    if (rc != NGX_DONE) {
        return rc;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header representation done");

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_literal(ngx_connection_t *c, ngx_http_v3_parse_literal_t *st,
    u_char ch)
{
    ngx_uint_t               n;
    ngx_http_v3_srv_conf_t  *v3cf;
    enum {
        sw_start = 0,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse literal huff:%ui, len:%ui",
                       st->huffman, st->length);

        n = st->length;

        v3cf = ngx_http_v3_get_module_srv_conf(c, ngx_http_v3_module);

        if (n > v3cf->max_field_size) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client exceeded http3_max_field_size limit");
            return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD;
        }

        if (st->huffman) {
            n = n * 8 / 5;
            st->huffstate = 0;
        }

        st->last = ngx_pnalloc(c->pool, n + 1);
        if (st->last == NULL) {
            return NGX_ERROR;
        }

        st->value.data = st->last;
        st->state = sw_value;

        /* fall through */

    case sw_value:

        if (st->huffman) {
            if (ngx_http_v2_huff_decode(&st->huffstate, &ch, 1, &st->last,
                                        st->length == 1, c->log)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else {
            *st->last++ = ch;
        }

        if (--st->length) {
            break;
        }

        st->value.len = st->last - st->value.data;
        *st->last = '\0';
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse literal done \"%V\"", &st->value);

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_ri(ngx_connection_t *c, ngx_http_v3_parse_header_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header ri");

        st->dynamic = (ch & 0x40) ? 0 : 1;
        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header ri done %s%ui]",
                   st->dynamic ? "dynamic[-" : "static[", st->index);

    if (st->dynamic) {
        st->index = st->base - st->index - 1;
    }

    rc = ngx_http_v3_parse_lookup(c, st->dynamic, st->index, &st->name,
                                  &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_lri(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header lri");

        st->dynamic = (ch & 0x10) ? 0 : 1;
        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 4, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->value = st->literal.value;
            goto done;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header lri done %s%ui] \"%V\"",
                   st->dynamic ? "dynamic[-" : "static[",
                   st->index, &st->value);

    if (st->dynamic) {
        st->index = st->base - st->index - 1;
    }

    rc = ngx_http_v3_parse_lookup(c, st->dynamic, st->index, &st->name, NULL);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_l(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_len,
        sw_name,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header l");

        st->literal.huffman = (ch & 0x08) ? 1 : 0;
        st->state = sw_name_len;

        /* fall through */

    case sw_name_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 3, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            return NGX_ERROR;
        }

        st->state = sw_name;
        break;

    case sw_name:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->name = st->literal.value;
            st->state = sw_value_len;
            break;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->value = st->literal.value;
            goto done;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header l done \"%V\" \"%V\"",
                   &st->name, &st->value);

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_pbi(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header pbi");

        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 4, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header pbi done dynamic[+%ui]", st->index);

    rc = ngx_http_v3_parse_lookup(c, 1, st->base + st->index, &st->name,
                                  &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_lpbi(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse header lpbi");

        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 3, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->value = st->literal.value;
            goto done;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header lpbi done dynamic[+%ui] \"%V\"",
                   st->index, &st->value);

    rc = ngx_http_v3_parse_lookup(c, 1, st->base + st->index, &st->name, NULL);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_lookup(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *name, ngx_str_t *value)
{
    u_char  *p;

    if (!dynamic) {
        if (ngx_http_v3_lookup_static(c, index, name, value) != NGX_OK) {
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        return NGX_OK;
    }

    if (ngx_http_v3_lookup(c, index, name, value) != NGX_OK) {
        return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    if (name) {
        p = ngx_pnalloc(c->pool, name->len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, name->data, name->len);
        p[name->len] = '\0';
        name->data = p;
    }

    if (value) {
        p = ngx_pnalloc(c->pool, value->len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, value->data, value->len);
        p[value->len] = '\0';
        value->data = p;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_parse_control(ngx_connection_t *c, void *data, u_char ch)
{
    ngx_http_v3_parse_control_t *st = data;

    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_first_type,
        sw_type,
        sw_length,
        sw_settings,
        sw_max_push_id,
        sw_skip
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse control");

        st->state = sw_first_type;

        /* fall through */

    case sw_first_type:
    case sw_type:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        st->type = st->vlint.value;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse frame type:%ui", st->type);

        if (st->state == sw_first_type
            && st->type != NGX_HTTP_V3_FRAME_SETTINGS)
        {
            return NGX_HTTP_V3_ERR_MISSING_SETTINGS;
        }

        st->state = sw_length;
        break;

    case sw_length:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse frame len:%uL", st->vlint.value);

        st->length = st->vlint.value;
        if (st->length == 0) {
            st->state = sw_type;
            break;
        }

        switch (st->type) {

        case NGX_HTTP_V3_FRAME_SETTINGS:
            st->state = sw_settings;
            break;

        case NGX_HTTP_V3_FRAME_MAX_PUSH_ID:
            st->state = sw_max_push_id;
            break;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse skip unknown frame");
            st->state = sw_skip;
        }

        break;

    case sw_settings:

        rc = ngx_http_v3_parse_settings(c, &st->settings, ch);

        st->length--;

        if (rc == NGX_AGAIN) {
            if (st->length == 0) {
                return NGX_HTTP_V3_ERR_SETTINGS_ERROR;
            }

            break;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        if (st->length == 0) {
            st->state = sw_type;
        }

        break;

    case sw_max_push_id:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse MAX_PUSH_ID:%uL", st->vlint.value);

        st->state = sw_type;
        break;

    case sw_skip:

        if (--st->length == 0) {
            st->state = sw_type;
        }

        break;
    }

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_v3_parse_settings(ngx_connection_t *c,
    ngx_http_v3_parse_settings_t *st, u_char ch)
{
    enum {
        sw_start = 0,
        sw_id,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse settings");

        st->state = sw_id;

        /* fall through */

    case sw_id:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        st->id = st->vlint.value;
        st->state = sw_value;
        break;

    case sw_value:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        if (ngx_http_v3_set_param(c, st->id, st->vlint.value) != NGX_OK) {
            return NGX_HTTP_V3_ERR_SETTINGS_ERROR;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse settings done");

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_encoder(ngx_connection_t *c, void *data, u_char ch)
{
    ngx_http_v3_parse_encoder_t *st = data;

    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_inr,
        sw_iwnr,
        sw_capacity,
        sw_duplicate
    };

    if (st->state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse encoder instruction");

        if (ch & 0x80) {
            /* Insert With Name Reference */

            st->state = sw_inr;

        } else if (ch & 0x40) {
            /*  Insert Without Name Reference */

            st->state = sw_iwnr;

        } else if (ch & 0x20) {
            /*  Set Dynamic Table Capacity */

            st->state = sw_capacity;

        } else {
            /* Duplicate */

            st->state = sw_duplicate;
        }
    }

    switch (st->state) {

    case sw_inr:

        rc = ngx_http_v3_parse_header_inr(c, &st->header, ch);

        if (rc == NGX_AGAIN) {
            break;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        goto done;

    case sw_iwnr:

        rc = ngx_http_v3_parse_header_iwnr(c, &st->header, ch);

        if (rc == NGX_AGAIN) {
            break;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        goto done;

    case sw_capacity:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 5, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_set_capacity(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;

    case sw_duplicate:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 5, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_duplicate(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse encoder instruction done");

    st->state = sw_start;
    return NGX_AGAIN;
}


ngx_int_t
ngx_http_v3_parse_header_inr(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse header inr");

        st->dynamic = (ch & 0x40) ? 0 : 1;
        st->state = sw_name_index;

        /* fall through */

    case sw_name_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->value = st->literal.value;
            goto done;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header inr done %s[%ui] \"%V\"",
                   st->dynamic ? "dynamic" : "static",
                   st->index, &st->value);

    rc = ngx_http_v3_ref_insert(c, st->dynamic, st->index, &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_header_iwnr(ngx_connection_t *c,
    ngx_http_v3_parse_header_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_len,
        sw_name,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse header iwnr");

        st->literal.huffman = (ch & 0x20) ? 1 : 0;
        st->state = sw_name_len;

        /* fall through */

    case sw_name_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 5, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            return NGX_ERROR;
        }

        st->state = sw_name;
        break;

    case sw_name:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->name = st->literal.value;
            st->state = sw_value_len;
            break;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);

        if (rc == NGX_DONE) {
            st->value = st->literal.value;
            goto done;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        break;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse header iwnr done \"%V\":\"%V\"",
                   &st->name, &st->value);

    rc = ngx_http_v3_insert(c, &st->name, &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_decoder(ngx_connection_t *c, void *data, u_char ch)
{
    ngx_http_v3_parse_decoder_t *st = data;

    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_ack_header,
        sw_cancel_stream,
        sw_inc_insert_count
    };

    if (st->state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse decoder instruction");

        if (ch & 0x80) {
            /* Header Acknowledgement */

            st->state = sw_ack_header;

        } else if (ch & 0x40) {
            /*  Stream Cancellation */

            st->state = sw_cancel_stream;

        }  else {
            /*  Insert Count Increment */

            st->state = sw_inc_insert_count;
        }
    }

    switch (st->state) {

    case sw_ack_header:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_ack_header(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;

    case sw_cancel_stream:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_cancel_stream(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;

    case sw_inc_insert_count:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_inc_insert_count(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse decoder instruction done");

    st->state = sw_start;
    return NGX_AGAIN;
}


ngx_int_t
ngx_http_v3_parse_data(ngx_connection_t *c, ngx_http_v3_parse_data_t *st,
    u_char ch)
{
    enum {
        sw_start = 0,
        sw_type,
        sw_length
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse data");

        st->state = sw_type;

        /* fall through */

    case sw_type:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        if (st->vlint.value != NGX_HTTP_V3_FRAME_DATA) {
            return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED;
        }

        st->state = sw_length;
        break;

    case sw_length:

        if (ngx_http_v3_parse_varlen_int(c, &st->vlint, ch) != NGX_DONE) {
            break;
        }

        st->length = st->vlint.value;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse data frame len:%ui", st->length);

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse data done");

    st->state = sw_start;
    return NGX_DONE;
}
