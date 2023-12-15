
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_
#define _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_QUIC_PATH_RETRIES   3

#define NGX_QUIC_PATH_PROBE     0
#define NGX_QUIC_PATH_ACTIVE    1
#define NGX_QUIC_PATH_BACKUP    2

#define ngx_quic_path_dbg(c, msg, path)                                       \
    ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,                            \
                   "quic path seq:%uL %s tx:%O rx:%O valid:%d st:%d mtu:%uz", \
                   path->seqnum, msg, path->sent, path->received,             \
                   path->validated, path->state, path->mtu);

ngx_int_t ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f);
ngx_int_t ngx_quic_handle_path_response_frame(ngx_connection_t *c,
    ngx_quic_path_challenge_frame_t *f);

ngx_quic_path_t *ngx_quic_new_path(ngx_connection_t *c,
    struct sockaddr *sockaddr, socklen_t socklen, ngx_quic_client_id_t *cid);
ngx_int_t ngx_quic_free_path(ngx_connection_t *c, ngx_quic_path_t *path);

ngx_int_t ngx_quic_set_path(ngx_connection_t *c, ngx_quic_header_t *pkt);
ngx_int_t ngx_quic_handle_migration(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

void ngx_quic_path_handler(ngx_event_t *ev);

void ngx_quic_discover_path_mtu(ngx_connection_t *c, ngx_quic_path_t *path);
ngx_int_t ngx_quic_handle_path_mtu(ngx_connection_t *c,
    ngx_quic_path_t *path, uint64_t min, uint64_t max);

#endif /* _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_ */
