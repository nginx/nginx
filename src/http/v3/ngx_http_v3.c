
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


uintptr_t
ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value)
{
    if (value <= 63) {
        if (p == NULL) {
            return 1;
        }

        *p++ = value;
        return (uintptr_t) p;
    }

    if (value <= 16383) {
        if (p == NULL) {
            return 2;
        }

        *p++ = 0x40 | (value >> 8);
        *p++ = value;
        return (uintptr_t) p;
    }

    if (value <= 1073741823) {
        if (p == NULL) {
            return 3;
        }

        *p++ = 0x80 | (value >> 16);
        *p++ = (value >> 8);
        *p++ = value;
        return (uintptr_t) p;

    }

    if (p == NULL) {
        return 4;
    }

    *p++ = 0xc0 | (value >> 24);
    *p++ = (value >> 16);
    *p++ = (value >> 8);
    *p++ = value;
    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_prefix_int(u_char *p, uint64_t value, ngx_uint_t prefix)
{
    ngx_uint_t  thresh, n;

    thresh = (1 << prefix) - 1;

    if (value < thresh) {
        if (p == NULL) {
            return 1;
        }

        *p++ |= value;
        return (uintptr_t) p;
    }

    value -= thresh;

    for (n = 10; n > 1; n--) {
        if (value >> (7 * (n - 1))) {
            break;
        }
    }

    if (p == NULL) {
        return n + 1;
    }

    *p++ |= thresh;

    for ( /* void */ ; n > 1; n--) {
        *p++ = 0x80 | (value >> 7 * (n - 1));
    }

    *p++ = value & 0x7f;

    return (uintptr_t) p;
}


uint64_t
ngx_http_v3_decode_varlen_int(u_char *p)
{
    uint64_t    value;
    ngx_uint_t  len;

    len = *p >> 6;
    value = *p & 0x3f;

    while (len--) {
        value = (value << 8) + *p++;
    }

    return value;
}


int64_t
ngx_http_v3_decode_prefix_int(u_char **src, size_t len, ngx_uint_t prefix)
{
    u_char   *p;
    int64_t   value, thresh;

    if (len == 0) {
        return NGX_ERROR;
    }

    p = *src;

    thresh = (1 << prefix) - 1;
    value = *p++ & thresh;

    if (value != thresh) {
        *src = p;
        return value;
    }

    value = 0;

    /* XXX handle overflows */

    while (--len) {
        value = (value << 7) + (*p & 0x7f);
        if ((*p++ & 0x80) == 0) {
            *src = p;
            return value + thresh;
        }
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_decode_huffman(ngx_connection_t *c, ngx_str_t *s)
{
    u_char  state, *p, *data;

    state = 0;

    p = ngx_pnalloc(c->pool, s->len * 8 / 5);
    if (p == NULL) {
        return NGX_ERROR;
    }

    data = p;

    if (ngx_http_v2_huff_decode(&state, s->data, s->len, &p, 1, c->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    s->len = p - data;
    s->data = data;

    return NGX_OK;
}
