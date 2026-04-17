
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

#define NGX_PROXY_PROTOCOL_AF_UNSPEC      0
#define NGX_PROXY_PROTOCOL_AF_INET        1
#define NGX_PROXY_PROTOCOL_AF_INET6       2
#define NGX_PROXY_PROTOCOL_AF_UNIX        3

#define NGX_PROXY_PROTOCOL_V2_TYPE_ALPN           0x01
#define NGX_PROXY_PROTOCOL_V2_TYPE_AUTHORITY      0x02
#define NGX_PROXY_PROTOCOL_V2_TYPE_CRC32C         0x03
#define NGX_PROXY_PROTOCOL_V2_TYPE_UNIQUE_ID      0x05
#define NGX_PROXY_PROTOCOL_V2_TYPE_SSL            0x20
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_VERSION 0x21
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CN      0x22
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CIPHER  0x23
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_SIG_ALG 0x24
#define NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_KEY_ALG 0x25
#define NGX_PROXY_PROTOCOL_V2_TYPE_NETNS          0x30

#define NGX_PROXY_PROTOCOL_V2_CLIENT_SSL          0x01
#define NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_CONN    0x02
#define NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_SESS    0x04


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


/* config-time TLV entry; cv is an opaque complex-value pointer */
typedef struct {
    ngx_uint_t          type;
    ngx_uint_t          is_ssl_sub;
    ngx_uint_t          is_ssl_verify;
    ngx_uint_t          is_ssl_raw;
    void               *cv;
} ngx_proxy_protocol_conf_tlv_t;


/* callback prototype for evaluating complex values; ctx is the request/session */
typedef ngx_int_t (*ngx_proxy_protocol_complex_value_pt)(void *ctx, void *cv,
    ngx_str_t *value);

typedef struct {
    ngx_proxy_protocol_complex_value_pt  complex_value;
    ngx_uint_t                           version;
    ngx_array_t                         *tlvs;
    ngx_flag_t                           crc32c;
} ngx_proxy_protocol_write_conf_t;


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
u_char *ngx_proxy_protocol_write_conf(ngx_connection_t *c,
    ngx_proxy_protocol_write_conf_t *conf, u_char **last);
ngx_int_t ngx_proxy_protocol_tlv_type(ngx_str_t *name, ngx_uint_t *typep,
    ngx_uint_t *is_ssl_subp, ngx_uint_t *is_ssl_verifyp,
    ngx_uint_t *is_ssl_rawp);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
size_t ngx_proxy_protocol_v2_tlvs_size(ngx_array_t *tlvs);
char *ngx_proxy_protocol_v2_add_tlv(ngx_conf_t *cf, ngx_array_t **tlvsp,
    ngx_str_t *name, void *cv);


#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
