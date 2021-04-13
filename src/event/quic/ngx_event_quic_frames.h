
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_FRAMES_H_INCLUDED_
#define _NGX_EVENT_QUIC_FRAMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_int_t (*ngx_quic_frame_handler_pt)(ngx_connection_t *c,
    ngx_quic_frame_t *frame, void *data);


ngx_quic_frame_t *ngx_quic_alloc_frame(ngx_connection_t *c);
void ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame);
void ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames);
void ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame);
ngx_int_t ngx_quic_split_frame(ngx_connection_t *c, ngx_quic_frame_t *f,
    size_t len);

ngx_chain_t *ngx_quic_alloc_buf(ngx_connection_t *c);
ngx_chain_t *ngx_quic_copy_buf(ngx_connection_t *c, u_char *data,
    size_t len);
ngx_chain_t *ngx_quic_copy_chain(ngx_connection_t *c, ngx_chain_t *in,
    size_t limit);

ngx_int_t ngx_quic_handle_ordered_frame(ngx_connection_t *c,
    ngx_quic_frames_stream_t *fs, ngx_quic_frame_t *frame,
    ngx_quic_frame_handler_pt handler, void *data);

#if (NGX_DEBUG)
void ngx_quic_log_frame(ngx_log_t *log, ngx_quic_frame_t *f, ngx_uint_t tx);
#else
#define ngx_quic_log_frame(log, f, tx)
#endif

#endif /* _NGX_EVENT_QUIC_FRAMES_H_INCLUDED_ */
