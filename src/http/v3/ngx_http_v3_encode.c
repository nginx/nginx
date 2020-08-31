
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
            return 4;
        }

        *p++ = 0x80 | (value >> 24);
        *p++ = (value >> 16);
        *p++ = (value >> 8);
        *p++ = value;
        return (uintptr_t) p;
    }

    if (p == NULL) {
        return 8;
    }

    *p++ = 0xc0 | (value >> 56);
    *p++ = (value >> 48);
    *p++ = (value >> 40);
    *p++ = (value >> 32);
    *p++ = (value >> 24);
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

    if (p == NULL) {
        for (n = 2; value >= 128; n++) {
            value >>= 7;
        }

        return n;
    }

    *p++ |= thresh;

    while (value >= 128) {
        *p++ = 0x80 | value;
        value >>= 7;
    }

    *p++ = value;

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_header_block_prefix(u_char *p, ngx_uint_t insert_count,
    ngx_uint_t sign, ngx_uint_t delta_base)
{
    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, insert_count, 8)
               + ngx_http_v3_encode_prefix_int(NULL, delta_base, 7);
    }

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, insert_count, 8);

    *p = sign ? 0x80 : 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, delta_base, 7);

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_header_ri(u_char *p, ngx_uint_t dynamic, ngx_uint_t index)
{
    /* Indexed Header Field */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 6);
    }

    *p = dynamic ? 0x80 : 0xc0;

    return ngx_http_v3_encode_prefix_int(p, index, 6);
}


uintptr_t
ngx_http_v3_encode_header_lri(u_char *p, ngx_uint_t dynamic, ngx_uint_t index,
    u_char *data, size_t len)
{
    /* Literal Header Field With Name Reference */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 4)
               + ngx_http_v3_encode_prefix_int(NULL, len, 7)
               + len;
    }

    *p = dynamic ? 0x40 : 0x50;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, index, 4);

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, len, 7);

    if (data) {
        p = ngx_cpymem(p, data, len);
    }

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_header_l(u_char *p, ngx_str_t *name, ngx_str_t *value)
{
    /* Literal Header Field Without Name Reference */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, name->len, 3)
               + name->len
               + ngx_http_v3_encode_prefix_int(NULL, value->len, 7)
               + value->len;
    }

    *p = 0x20;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, name->len, 3);

    ngx_strlow(p, name->data, name->len);
    p += name->len;

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, value->len, 7);

    p = ngx_cpymem(p, value->data, value->len);

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_header_pbi(u_char *p, ngx_uint_t index)
{
    /* Indexed Header Field With Post-Base Index */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 4);
    }

    *p = 0x10;

    return ngx_http_v3_encode_prefix_int(p, index, 4);
}


uintptr_t
ngx_http_v3_encode_header_lpbi(u_char *p, ngx_uint_t index, u_char *data,
    size_t len)
{
    /* Literal Header Field With Post-Base Name Reference */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 3)
               + ngx_http_v3_encode_prefix_int(NULL, len, 7)
               + len;
    }

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, index, 3);

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, len, 7);

    if (data) {
        p = ngx_cpymem(p, data, len);
    }

    return (uintptr_t) p;
}
