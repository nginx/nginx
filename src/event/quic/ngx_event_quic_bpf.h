
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_BPF_H_INCLUDED_
#define _NGX_EVENT_QUIC_BPF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_bpf_get_client_fd(ngx_connection_t *lc,
    ngx_socket_t *fd);
ngx_int_t ngx_quic_bpf_insert(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock);
ngx_int_t ngx_quic_bpf_delete(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock);


#endif /* _NGX_EVENT_QUIC_BPF_H_INCLUDED_ */
