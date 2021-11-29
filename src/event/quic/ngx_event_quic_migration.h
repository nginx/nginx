
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_
#define _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_QUIC_PATH_RETRIES          3

#define NGX_QUIC_PATH_NEW              0
#define NGX_QUIC_PATH_VALIDATING       1
#define NGX_QUIC_PATH_VALIDATED        2

#define NGX_QUIC_PATH_VALID_TIME       600 /* seconds */


#define ngx_quic_path_state_str(p)                                            \
    ((p)->state == NGX_QUIC_PATH_NEW) ? "new" :                               \
        (((p)->state == NGX_QUIC_PATH_VALIDATED) ? "validated" : "validating")


ngx_int_t ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_path_challenge_frame_t *f);
ngx_int_t ngx_quic_handle_path_response_frame(ngx_connection_t *c,
    ngx_quic_path_challenge_frame_t *f);

ngx_quic_path_t *ngx_quic_find_path(ngx_connection_t *c,
    struct sockaddr *sockaddr, socklen_t socklen);
ngx_quic_path_t *ngx_quic_add_path(ngx_connection_t *c,
    struct sockaddr *sockaddr, socklen_t socklen);

ngx_int_t ngx_quic_update_paths(ngx_connection_t *c, ngx_quic_header_t *pkt);
ngx_int_t ngx_quic_handle_migration(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

void ngx_quic_path_validation_handler(ngx_event_t *ev);

#endif /* _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_ */
