
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static u_char *ngx_http_v2_write_int(u_char *pos, ngx_uint_t prefix,
    ngx_uint_t value);


u_char *
ngx_http_v2_string_encode(u_char *dst, u_char *src, size_t len, u_char *tmp,
    ngx_uint_t lower)
{
    size_t  hlen;

    hlen = ngx_http_huff_encode(src, len, tmp, lower);

    if (hlen > 0) {
        *dst = NGX_HTTP_V2_ENCODE_HUFF;
        dst = ngx_http_v2_write_int(dst, ngx_http_v2_prefix(7), hlen);
        return ngx_cpymem(dst, tmp, hlen);
    }

    *dst = NGX_HTTP_V2_ENCODE_RAW;
    dst = ngx_http_v2_write_int(dst, ngx_http_v2_prefix(7), len);

    if (lower) {
        ngx_strlow(dst, src, len);
        return dst + len;
    }

    return ngx_cpymem(dst, src, len);
}


static u_char *
ngx_http_v2_write_int(u_char *pos, ngx_uint_t prefix, ngx_uint_t value)
{
    if (value < prefix) {
        *pos++ |= value;
        return pos;
    }

    *pos++ |= prefix;
    value -= prefix;

    while (value >= 128) {
        *pos++ = value % 128 + 128;
        value /= 128;
    }

    *pos++ = (u_char) value;

    return pos;
}
