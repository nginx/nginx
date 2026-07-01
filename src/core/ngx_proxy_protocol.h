
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_

#include "ngx_string.h"
#include <stdint.h>
#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_PROXY_PROTOCOL_V1_MAX_HEADER 107
#define NGX_PROXY_PROTOCOL_V2_MAX_HEADER 64
#define NGX_PROXY_PROTOCOL_MAX_HEADER 4096

struct ngx_proxy_protocol_s {
  ngx_str_t src_addr;
  ngx_str_t dst_addr;
  in_port_t src_port;
  in_port_t dst_port;
  ngx_str_t tlvs;
};

typedef struct {
  u_char *pos;
  u_char  len;
} ngx_proxy_protocol_tlv_buf_t;

typedef struct {
  uint8_t   type;
  uint16_t  length;
  ngx_str_t value;
} ngx_proxy_v2_tlv;

u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
                                 u_char *last);
u_char *ngx_proxy_protocol_v2_write(ngx_connection_t *c, u_char *buf,
                                    u_char *last);
ngx_int_t ngx_proxy_protocol_v2_build_tlv(ngx_connection_t *c, ngx_proxy_v2_tlv *tlvs,
                                ngx_uint_t n);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
                                     ngx_str_t *value);


#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
