
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_SOCKET_H_INCLUDED_
#define _NGX_EVENT_QUIC_SOCKET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_open_sockets(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_header_t *pkt);
void ngx_quic_close_sockets(ngx_connection_t *c);

ngx_quic_socket_t *ngx_quic_create_socket(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
ngx_int_t ngx_quic_listen(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock);
void ngx_quic_close_socket(ngx_connection_t *c, ngx_quic_socket_t *qsock);

ngx_quic_socket_t *ngx_quic_find_socket(ngx_connection_t *c, uint64_t seqnum);


#endif /* _NGX_EVENT_QUIC_SOCKET_H_INCLUDED_ */
