
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PROXY_PROTOCOL_MAX_HEADER     4096


struct ngx_proxy_protocol_s {
    ngx_str_t           src_addr;
    ngx_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
    ngx_str_t           tlvs;
};


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
u_char *ngx_proxy_protocol_write_conf(ngx_connection_t *c,
    ngx_proxy_protocol_write_conf_t *conf, u_char **last);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);
char *ngx_proxy_protocol_v2_add_tlv(ngx_conf_t *cf, ngx_array_t **tlvsp,
    ngx_str_t *name, void *cv);


#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
