
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_CONNID_H_INCLUDED_
#define _NGX_EVENT_QUIC_CONNID_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    ngx_flag_t            enabled;
    ngx_uint_t            map_size;
    int                   worker_map_fd;
    ngx_queue_t           groups;     /* of ngx_quic_sock_group_t */
} ngx_quic_bpf_conf_t;

extern ngx_module_t ngx_quic_bpf_module;
#define ngx_quic_bpf_get_conf(cycle)                                          \
    (ngx_quic_bpf_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_quic_bpf_module)

// shuttingdown worker use magic_cid to redirect received new quic conn to new worker.
// 0x6e67696e78 refers to "nginx".
#define REDIRECT_WORKER_CID_MAGIC 0x6e67696e78000000ULL

ngx_int_t ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_retire_cid_frame_t *f);
ngx_int_t ngx_quic_handle_new_connection_id_frame(ngx_connection_t *c,
    ngx_quic_new_conn_id_frame_t *f);

ngx_int_t ngx_quic_create_sockets(ngx_connection_t *c);
ngx_int_t ngx_quic_create_server_id(ngx_connection_t *c, u_char *id);

ngx_quic_client_id_t *ngx_quic_create_client_id(ngx_connection_t *c,
    ngx_str_t *id, uint64_t seqnum, u_char *token);
ngx_quic_client_id_t *ngx_quic_next_client_id(ngx_connection_t *c);
ngx_int_t ngx_quic_free_client_id(ngx_connection_t *c,
    ngx_quic_client_id_t *cid);

#endif /* _NGX_EVENT_QUIC_CONNID_H_INCLUDED_ */
