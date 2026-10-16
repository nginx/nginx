
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PROXY_PROTOCOL_V1_MAX_HEADER  107
#define NGX_PROXY_PROTOCOL_MAX_HEADER     4096

/*
 * TLV types reserved by the PROXY protocol specification for use by
 * applications: 0xe0 - 0xef custom, 0xf0 - 0xf7 experimental,
 * 0xf8 - 0xff future.
 */

#define NGX_PROXY_PROTOCOL_TLV_USER_MIN   0xe0
#define NGX_PROXY_PROTOCOL_TLV_USER_MAX   0xff


struct ngx_proxy_protocol_s {
    ngx_str_t           src_addr;
    ngx_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
    ngx_str_t           tlvs;
};


typedef struct {
    ngx_uint_t          type;
    ngx_str_t           value;
} ngx_proxy_protocol_tlv_value_t;


u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_v2_write(ngx_connection_t *c, u_char *buf,
    u_char *last, ngx_array_t *tlvs);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
ngx_int_t ngx_proxy_protocol_v2_tlv_type(ngx_str_t *s, ngx_uint_t *type);


#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
