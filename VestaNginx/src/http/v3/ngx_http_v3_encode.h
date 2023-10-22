
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_ENCODE_H_INCLUDED_
#define _NGX_HTTP_V3_ENCODE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


uintptr_t ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value);
uintptr_t ngx_http_v3_encode_prefix_int(u_char *p, uint64_t value,
    ngx_uint_t prefix);

uintptr_t ngx_http_v3_encode_field_section_prefix(u_char *p,
    ngx_uint_t insert_count, ngx_uint_t sign, ngx_uint_t delta_base);
uintptr_t ngx_http_v3_encode_field_ri(u_char *p, ngx_uint_t dynamic,
    ngx_uint_t index);
uintptr_t ngx_http_v3_encode_field_lri(u_char *p, ngx_uint_t dynamic,
    ngx_uint_t index, u_char *data, size_t len);
uintptr_t ngx_http_v3_encode_field_l(u_char *p, ngx_str_t *name,
    ngx_str_t *value);
uintptr_t ngx_http_v3_encode_field_pbi(u_char *p, ngx_uint_t index);
uintptr_t ngx_http_v3_encode_field_lpbi(u_char *p, ngx_uint_t index,
    u_char *data, size_t len);


#endif /* _NGX_HTTP_V3_ENCODE_H_INCLUDED_ */
