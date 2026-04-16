/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_QLOG_H_INCLUDED_
#define _NGX_EVENT_QUIC_QLOG_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic.h>
#include <ngx_event_quic_connection.h>


typedef enum {
    NGX_QUIC_QLOG_SIDE_LOCAL = 0,
    NGX_QUIC_QLOG_SIDE_REMOTE
} ngx_quic_qlog_side_e;


typedef enum {
    NGX_QUIC_QLOG_PKT_LOST_TIME = 0,
    NGX_QUIC_QLOG_PKT_LOST_REORDERING
} ngx_quic_qlog_pkt_lost_e;


#if (NGX_QUIC_QLOG)

typedef struct ngx_quic_qlog_s  ngx_quic_qlog_t;


ngx_int_t ngx_quic_qlog_init(ngx_connection_t *c, ngx_quic_connection_t *qc);
void ngx_quic_qlog_close(ngx_quic_connection_t *qc);

void ngx_quic_qlog_connection_started(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_connection_closed(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_transport_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_tp_t *params,
    ngx_quic_qlog_side_e side);
void ngx_quic_qlog_metrics_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_pkt_lost(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_send_ctx_t *ctx, ngx_quic_frame_t *start,
    ngx_quic_qlog_pkt_lost_e trigger);

void ngx_quic_qlog_pkt_received_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_pkt_received_end(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_header_t *pkt);
void ngx_quic_qlog_pkt_sent_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_pkt_sent_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
void ngx_quic_qlog_write_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *f);

#else /* NGX_QUIC_QLOG */

#define ngx_quic_qlog_init(c, qc)  NGX_OK
#define ngx_quic_qlog_close(qc)
#define ngx_quic_qlog_connection_started(c, qc)
#define ngx_quic_qlog_connection_closed(c, qc)
#define ngx_quic_qlog_transport_parameters_set(c, qc, params, side)
#define ngx_quic_qlog_metrics_updated(c, qc)
#define ngx_quic_qlog_pkt_lost(c, qc, ctx, start, trigger)
#define ngx_quic_qlog_pkt_received_start(c, qc)
#define ngx_quic_qlog_pkt_received_end(c, qc, pkt)
#define ngx_quic_qlog_pkt_sent_start(c, qc)
#define ngx_quic_qlog_pkt_sent_end(c, qc, pkt)
#define ngx_quic_qlog_write_frame(qc, f)

#endif /* NGX_QUIC_QLOG */


#endif /* _NGX_EVENT_QUIC_QLOG_H_INCLUDED_ */
