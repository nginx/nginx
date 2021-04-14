
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_
#define _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f);
ngx_int_t ngx_quic_handle_path_response_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f);

#endif /* _NGX_EVENT_QUIC_MIGRATION_H_INCLUDED_ */
