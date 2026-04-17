
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PROXY_PROTOCOL_V1_MAX_HEADER  107
#define NGX_PROXY_PROTOCOL_V2_MAX_HEADER  232
#define NGX_PROXY_PROTOCOL_MAX_HEADER     4096


struct ngx_proxy_protocol_s {
    ngx_str_t           src_addr;
    ngx_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
    ngx_str_t           tlvs;
};


typedef struct {
    ngx_uint_t          type;         /* 0-255 */
    ngx_str_t           value;
    ngx_uint_t          is_ssl_sub;   /* sub-TLV inside PP2_TYPE_SSL */
    ngx_uint_t          is_ssl_verify;/* ssl_verify field, not a wire TLV */
    ngx_uint_t          is_ssl_raw;   /* raw PP2_TYPE_SSL body passthrough */
} ngx_proxy_protocol_write_tlv_t;


u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_v2_write(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_v2_write_tlvs(ngx_connection_t *c, u_char *buf,
    u_char *last, ngx_array_t *tlvs);
u_char *ngx_proxy_protocol_v2_write_crc32c(ngx_connection_t *c, u_char *buf,
    u_char *p, u_char *last);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);


#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
