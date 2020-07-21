
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_HTTP_QUIC_H_INCLUDED_
#define _NGX_HTTP_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_QUIC_ALPN(s)         NGX_HTTP_QUIC_ALPN_DRAFT(s)
#define NGX_HTTP_QUIC_ALPN_DRAFT(s)   "\x05hq-" #s
#define NGX_HTTP_QUIC_ALPN_ADVERTISE  NGX_HTTP_QUIC_ALPN(NGX_QUIC_DRAFT_VERSION)


extern ngx_module_t  ngx_http_quic_module;


#endif /* _NGX_HTTP_QUIC_H_INCLUDED_ */
