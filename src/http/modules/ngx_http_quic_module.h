
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_HTTP_QUIC_H_INCLUDED_
#define _NGX_HTTP_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_QUIC_ALPN_ADVERTISE  "\x02hq"
#define NGX_HTTP_QUIC_ALPN_DRAFT_FMT  "\x05hq-%02uD"


ngx_int_t ngx_http_quic_init(ngx_connection_t *c);


#endif /* _NGX_HTTP_QUIC_H_INCLUDED_ */
