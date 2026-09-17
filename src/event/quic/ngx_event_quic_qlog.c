/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic.h>
#include <ngx_event_quic_qlog.h>

#if (NGX_QUIC_QLOG)


#define NGX_QUIC_QLOG_BUF_SIZE      (16 * 1024)
#define NGX_QUIC_QLOG_OUT_BUF_SIZE  (8  * 1024)


#define ngx_qlog_write_literal(p, end, s)                                    \
    do {                                                                     \
        size_t n = ((p) < (end)) ? (size_t) ((end) - (p)) : 0;               \
        if (n > sizeof(s) - 1) {                                             \
            n = sizeof(s) - 1;                                               \
        }                                                                    \
        (p) = ngx_cpymem(p, s, n);                                           \
    } while (0)

#define ngx_qlog_write(p, end, fmt, ...)                                     \
    (p = ngx_slprintf(p, end, fmt, ##__VA_ARGS__))

#define ngx_qlog_write_char(p, end, c)                                       \
    do {                                                                     \
        if ((p) < (end)) {                                                   \
            *(p)++ = (c);                                                    \
        }                                                                    \
    } while (0)

#define ngx_qlog_write_pair(p, end, key, fmt, ...)                           \
    (p = ngx_slprintf(p, end, "\"%s\":" fmt, key, ##__VA_ARGS__))

#define ngx_qlog_write_pair_num(p, end, key, val)                            \
    ngx_qlog_write_pair(p, end, key, "%uL", (uint64_t)val)

#define ngx_qlog_write_pair_bool(p, end, key, val)                           \
    ngx_qlog_write_pair(p, end, key, "%s", (val) ? "true" : "false")

#define ngx_qlog_write_pair_str(p, end, key, val)                            \
    ngx_qlog_write_pair(p, end, key, "\"%s\"", val)

#define ngx_qlog_write_pair_strv(p, end, key, val)                           \
    ngx_qlog_write_pair(p, end, key, "\"%V\"", val)

#define ngx_qlog_write_pair_hex(p, end, key, val, len)                       \
    ngx_qlog_write_pair(p, end, key, "\"%*xs\"", (size_t) len, val)

#define ngx_qlog_write_pair_duration(p, end, key, val)                       \
    ngx_qlog_write_pair(p, end, key, "%M", val)


struct ngx_quic_qlog_s {
    ngx_fd_t    fd;
    ngx_str_t   path;

    u_char     *buf;
    u_char     *last;
    u_char     *end;

    ngx_log_t  *log;

    ngx_msec_t  start_time;

    ngx_uint_t  importance;

    size_t      bytes_written;
    size_t      max_size;

    unsigned    sent:1;
    unsigned    closed:1;

    /* previous metrics for dedup */
    ngx_msec_t  prev_min_rtt;
    ngx_msec_t  prev_avg_rtt;
    ngx_msec_t  prev_latest_rtt;
    ngx_msec_t  prev_rttvar;
    ngx_uint_t  prev_pto_count;
    size_t      prev_cwnd;
    size_t      prev_in_flight;
    size_t      prev_ssthresh;
};


/*
 * Per-worker shared buffers for qlog output.
 *
 * ngx_quic_qlog_buf/end: scratch buffer used by each connection to format
 * a single event before copying to the output buffer.
 *
 * ngx_quic_qlog_out_buf/end/last: output buffer that accumulates events
 * before flushing to disk.  Only one connection "owns" this buffer at a time,
 * tracked by ngx_quic_qlog_out_owner.  When a different connection needs to
 * write, the current owner's pending data is flushed first.
 */

static u_char *ngx_quic_qlog_buf;
static u_char *ngx_quic_qlog_end;
static u_char *ngx_quic_qlog_out_buf;
static u_char *ngx_quic_qlog_out_end;
static u_char *ngx_quic_qlog_out_last;

static ngx_quic_qlog_t *ngx_quic_qlog_out_owner;


static ngx_int_t ngx_quic_qlog_init_worker_buffers(void);
static ngx_int_t ngx_quic_qlog_open(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
static void ngx_quic_qlog_write_start(ngx_quic_connection_t *qc,
    ngx_uint_t sent);
static void ngx_quic_qlog_write_end(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_header_t *pkt, uint64_t pkt_number);
static ngx_int_t ngx_quic_qlog_write(ngx_quic_qlog_t *qlog, u_char *buf,
    size_t size);
static ngx_int_t ngx_quic_qlog_flush(ngx_quic_qlog_t *qlog);
static ngx_int_t ngx_quic_qlog_write_fd(ngx_quic_qlog_t *qlog, u_char *buf,
    size_t size);
static ngx_int_t ngx_quic_qlog_write_header(ngx_connection_t *c,
    ngx_quic_connection_t *qc, uint64_t reference_time_ms);
static ngx_quic_qlog_t * ngx_quic_qlog_start_event(ngx_quic_qlog_t *qlog,
    u_char **pp, u_char **pend, ngx_uint_t min_importance, const char *name);
static const char *ngx_quic_qlog_packet_name(uint8_t flags);
static const char *ngx_quic_qlog_packet_name_by_level(ngx_uint_t level);
static u_char *ngx_quic_qlog_padding_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_ping_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_ack_frame(u_char *p, u_char *end,
    ngx_quic_connection_t *qc, ngx_log_t *log, ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_reset_stream_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_stop_sending_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_crypto_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_new_token_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_stream_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_max_data_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_max_stream_data_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_max_streams_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_data_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_stream_data_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_streams_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_new_connection_id_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_retire_connection_id_frame(u_char *p,
    u_char *end, ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_path_challenge_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_path_response_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_connection_close_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_handshake_done_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);


ngx_int_t
ngx_quic_qlog_init(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    uint64_t     reference_time_ms;
    ngx_time_t  *tp;

    if (!qc->conf->qlog_enabled) {
        return NGX_DECLINED;
    }

    if (qc->conf->qlog_allow) {
        if (ngx_cidr_match(c->sockaddr, qc->conf->qlog_allow) != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    if (qc->conf->qlog_sample_n > 1) {
        if ((ngx_uint_t) ngx_random() % qc->conf->qlog_sample_n != 0) {
            return NGX_DECLINED;
        }
    }

    qc->qlog = ngx_pcalloc(c->pool, sizeof(ngx_quic_qlog_t));
    if (qc->qlog == NULL) {
        return NGX_ERROR;
    }

    qc->qlog->fd = NGX_INVALID_FILE;

    if (ngx_quic_qlog_init_worker_buffers() != NGX_OK) {
        qc->qlog->closed = 1;
        return NGX_ERROR;
    }

    qc->qlog->buf = ngx_quic_qlog_buf;
    qc->qlog->end = ngx_quic_qlog_end;
    qc->qlog->last = qc->qlog->buf;

    qc->qlog->log = c->log;

    qc->qlog->importance = qc->conf->qlog_importance;
    qc->qlog->max_size = qc->conf->qlog_max_size;

    if (ngx_quic_qlog_open(c, qc) != NGX_OK) {
        qc->qlog->closed = 1;
        return NGX_ERROR;
    }

    tp = ngx_timeofday();
    reference_time_ms = (uint64_t) tp->sec * 1000 + tp->msec;
    qc->qlog->start_time = ngx_current_msec;

    if (ngx_quic_qlog_write_header(c, qc, reference_time_ms) != NGX_OK) {
        ngx_close_file(qc->qlog->fd);
        qc->qlog->fd = NGX_INVALID_FILE;
        qc->qlog->closed = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_quic_qlog_close(ngx_quic_connection_t *qc)
{
    if (qc->qlog && qc->qlog->fd != NGX_INVALID_FILE) {
        (void) ngx_quic_qlog_flush(qc->qlog);
        ngx_close_file(qc->qlog->fd);
        qc->qlog->fd = NGX_INVALID_FILE;
        qc->qlog->closed = 1;
    }
}


void
ngx_quic_qlog_connection_started(ngx_connection_t *c,
    ngx_quic_connection_t *qc)
{
    u_char           *p, *end;
    u_char            src_text[NGX_SOCKADDR_STRLEN];
    u_char            dst_text[NGX_SOCKADDR_STRLEN];
    size_t            src_len, dst_len;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(qc->qlog, &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_BASE,
                                     "connectivity:connection_started");
    if (qlog == NULL) {
        return;
    }

    src_len = ngx_sock_ntop(c->sockaddr, c->socklen,
                            src_text, NGX_SOCKADDR_STRLEN, 0);
    dst_len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen,
                            dst_text, NGX_SOCKADDR_STRLEN, 0);

    ngx_qlog_write_pair_str(p, end, "ip_version",
                            c->sockaddr->sa_family == AF_INET6 ? "v6" : "v4");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write(p, end, "\"src_ip\":\"%*s\"", src_len, src_text);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "src_port",
                            ngx_inet_get_port(c->sockaddr));
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write(p, end, "\"dst_ip\":\"%*s\"", dst_len, dst_text);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "dst_port",
                            ngx_inet_get_port(c->local_sockaddr));
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_quic_qlog_connection_closed(ngx_connection_t *c,
    ngx_quic_connection_t *qc)
{
    u_char           *p, *end;
    const char       *trigger;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(qc->qlog, &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_BASE,
                                     "connectivity:connection_closed");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_pair_str(p, end, "owner",
                            qc->draining ? "remote" : "local");

    if (qc->error) {
        ngx_qlog_write_char(p, end, ',');

        if (qc->error_app) {
            ngx_qlog_write_pair_num(p, end, "application_code", qc->error);
        } else {
            ngx_qlog_write_pair_num(p, end, "connection_code", qc->error);
        }

        if (qc->error_reason) {
            ngx_qlog_write_char(p, end, ',');
            ngx_qlog_write_pair_str(p, end, "reason", qc->error_reason);
        }
    }

    if (qc->error == 0) {
        trigger = "clean";
    } else if (qc->error_app) {
        trigger = "application";
    } else {
        trigger = "error";
    }

    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "trigger", trigger);
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_quic_qlog_transport_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_tp_t *params, ngx_quic_qlog_side_e side)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(qc->qlog, &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_CORE,
                                     "transport:parameters_set");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_pair_str(p, end, "owner",
                            side == NGX_QUIC_QLOG_SIDE_LOCAL
                            ? "local" : "remote");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_hex(p, end, "initial_source_connection_id",
                            params->initial_scid.data,
                            params->initial_scid.len);
    ngx_qlog_write_char(p, end, ',');
    if (side == NGX_QUIC_QLOG_SIDE_LOCAL) {
        ngx_qlog_write_pair_hex(p, end, "original_destination_connection_id",
                                params->original_dcid.data,
                                params->original_dcid.len);
        ngx_qlog_write_char(p, end, ',');
    }
    if (params->retry_scid.len) {
        ngx_qlog_write_pair_hex(p, end, "retry_source_connection_id",
                                params->retry_scid.data,
                                params->retry_scid.len);
        ngx_qlog_write_char(p, end, ',');
    }
    ngx_qlog_write_pair_hex(p, end, "stateless_reset_token",
                            params->sr_token, NGX_QUIC_SR_TOKEN_LEN);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_bool(p, end, "disable_active_migration",
                             params->disable_active_migration);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_duration(p, end, "max_idle_timeout",
                                 params->max_idle_timeout);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "max_udp_payload_size",
                            params->max_udp_payload_size);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "ack_delay_exponent",
                            params->ack_delay_exponent);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_duration(p, end, "max_ack_delay",
                                 params->max_ack_delay);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "active_connection_id_limit",
                            params->active_connection_id_limit);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_data",
                            params->initial_max_data);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_stream_data_bidi_local",
                            params->initial_max_stream_data_bidi_local);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_stream_data_bidi_remote",
                            params->initial_max_stream_data_bidi_remote);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_stream_data_uni",
                            params->initial_max_stream_data_uni);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_streams_bidi",
                            params->initial_max_streams_bidi);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_streams_uni",
                            params->initial_max_streams_uni);
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_quic_qlog_metrics_updated(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    u_char           *p, *end;
    ngx_uint_t        first;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(qc->qlog, &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_CORE,
                                     "recovery:metrics_updated");
    if (qlog == NULL) {
        return;
    }

    if (qc->min_rtt == qlog->prev_min_rtt
        && qc->avg_rtt == qlog->prev_avg_rtt
        && qc->latest_rtt == qlog->prev_latest_rtt
        && qc->rttvar == qlog->prev_rttvar
        && qc->pto_count == qlog->prev_pto_count
        && qc->congestion.window == qlog->prev_cwnd
        && qc->congestion.in_flight == qlog->prev_in_flight
        && qc->congestion.ssthresh == qlog->prev_ssthresh)
    {
        return;
    }

    first = 1;

    if (qc->min_rtt != NGX_TIMER_INFINITE
        && qc->min_rtt != qlog->prev_min_rtt)
    {
        ngx_qlog_write_pair_duration(p, end, "min_rtt", qc->min_rtt);
        first = 0;
    }

    if (qc->avg_rtt != qlog->prev_avg_rtt) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_duration(p, end, "smoothed_rtt", qc->avg_rtt);
        first = 0;
    }

    if (qc->latest_rtt != qlog->prev_latest_rtt) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_duration(p, end, "latest_rtt", qc->latest_rtt);
        first = 0;
    }

    if (qc->rttvar != qlog->prev_rttvar) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_duration(p, end, "rtt_variance", qc->rttvar);
        first = 0;
    }

    if (qc->pto_count != qlog->prev_pto_count) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_num(p, end, "pto_count", qc->pto_count);
        first = 0;
    }

    if (qc->congestion.window != qlog->prev_cwnd) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_num(p, end, "congestion_window",
                                qc->congestion.window);
        first = 0;
    }

    if (qc->congestion.in_flight != qlog->prev_in_flight) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_num(p, end, "bytes_in_flight",
                                qc->congestion.in_flight);
        first = 0;
    }

    if (qc->congestion.ssthresh != qlog->prev_ssthresh) {
        if (!first) {
            ngx_qlog_write_char(p, end, ',');
        }
        ngx_qlog_write_pair_num(p, end, "ssthresh", qc->congestion.ssthresh);
    }

    qlog->prev_min_rtt = qc->min_rtt;
    qlog->prev_avg_rtt = qc->avg_rtt;
    qlog->prev_latest_rtt = qc->latest_rtt;
    qlog->prev_rttvar = qc->rttvar;
    qlog->prev_pto_count = qc->pto_count;
    qlog->prev_cwnd = qc->congestion.window;
    qlog->prev_in_flight = qc->congestion.in_flight;
    qlog->prev_ssthresh = qc->congestion.ssthresh;

    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_quic_qlog_pkt_lost(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_send_ctx_t *ctx, ngx_quic_frame_t *start,
    ngx_quic_qlog_pkt_lost_e trigger)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(qc->qlog, &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_CORE,
                                     "recovery:packet_lost");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, "\"header\":{");
    ngx_qlog_write_pair_str(p, end, "packet_type",
                            ngx_quic_qlog_packet_name_by_level(ctx->level));
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "packet_number", start->pnum);
    ngx_qlog_write_char(p, end, '}');
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "trigger",
                            trigger == NGX_QUIC_QLOG_PKT_LOST_TIME
                            ? "time_threshold"
                            : "reordering_threshold");
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_quic_qlog_pkt_received_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc)
{
    ngx_quic_qlog_write_start(qc, 0);
}


void
ngx_quic_qlog_pkt_received_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt)
{
    ngx_quic_qlog_write_end(c, qc, pkt, pkt->pn);
}


void
ngx_quic_qlog_pkt_sent_start(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_quic_qlog_write_start(qc, 1);
}


void
ngx_quic_qlog_pkt_sent_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt)
{
    ngx_quic_qlog_write_end(c, qc, pkt, pkt->number);
}


void
ngx_quic_qlog_write_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *f)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    p = qlog->last;
    end = qlog->end;

    switch (f->type) {
    case NGX_QUIC_FT_PADDING:
        p = ngx_quic_qlog_padding_frame(p, end, f);
        break;
    case NGX_QUIC_FT_PING:
        p = ngx_quic_qlog_ping_frame(p, end, f);
        break;
    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:
        p = ngx_quic_qlog_ack_frame(p, end, qc, qlog->log, f);
        break;
    case NGX_QUIC_FT_RESET_STREAM:
        p = ngx_quic_qlog_reset_stream_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STOP_SENDING:
        p = ngx_quic_qlog_stop_sending_frame(p, end, f);
        break;
    case NGX_QUIC_FT_CRYPTO:
        p = ngx_quic_qlog_crypto_frame(p, end, f);
        break;
    case NGX_QUIC_FT_NEW_TOKEN:
        p = ngx_quic_qlog_new_token_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STREAM:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:
        p = ngx_quic_qlog_stream_frame(p, end, f);
        break;
    case NGX_QUIC_FT_MAX_DATA:
        p = ngx_quic_qlog_max_data_frame(p, end, f);
        break;
    case NGX_QUIC_FT_MAX_STREAM_DATA:
        p = ngx_quic_qlog_max_stream_data_frame(p, end, f);
        break;
    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:
        p = ngx_quic_qlog_max_streams_frame(p, end, f);
        break;
    case NGX_QUIC_FT_DATA_BLOCKED:
        p = ngx_quic_qlog_data_blocked_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:
        p = ngx_quic_qlog_stream_data_blocked_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:
        p = ngx_quic_qlog_streams_blocked_frame(p, end, f);
        break;
    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        p = ngx_quic_qlog_new_connection_id_frame(p, end, f);
        break;
    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        p = ngx_quic_qlog_retire_connection_id_frame(p, end, f);
        break;
    case NGX_QUIC_FT_PATH_CHALLENGE:
        p = ngx_quic_qlog_path_challenge_frame(p, end, f);
        break;
    case NGX_QUIC_FT_PATH_RESPONSE:
        p = ngx_quic_qlog_path_response_frame(p, end, f);
        break;
    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        p = ngx_quic_qlog_connection_close_frame(p, end, f);
        break;
    case NGX_QUIC_FT_HANDSHAKE_DONE:
        p = ngx_quic_qlog_handshake_done_frame(p, end, f);
        break;
    default:
        ngx_qlog_write_literal(p, end, "{\"frame_type\":\"unknown\"}");
    }

    ngx_qlog_write_char(p, end, ',');

    qlog->last = p;
}


static void
ngx_quic_qlog_write_start(ngx_quic_connection_t *qc, ngx_uint_t sent)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    qlog->last = qlog->buf;
    qlog->sent = sent;

    if (ngx_quic_qlog_start_event(qlog, &p, &end, NGX_QUIC_QLOG_LEVEL_CORE,
                                  qlog->sent ? "transport:packet_sent"
                                             : "transport:packet_received")
        == NULL)
    {
        return;
    }

    ngx_qlog_write_literal(p, end, "\"frames\":[");
    qlog->last = p;
}


static void
ngx_quic_qlog_write_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt, uint64_t pkt_number)
{
    size_t            size;
    ngx_quic_qlog_t  *qlog;

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    if (qlog->last > qlog->buf && *(qlog->last - 1) == ',') {
        qlog->last--;
    }

    ngx_qlog_write(qlog->last, qlog->end,
                   "],\"header\":{\"packet_type\":\"%s\","
                   "\"packet_number\":%uL},"
                   "\"raw\":{\"length\":%uz}}}\n",
                   ngx_quic_qlog_packet_name(pkt->flags),
                   pkt_number,
                   pkt->len);

    size = qlog->last - qlog->buf;

    ngx_quic_qlog_write(qlog, qlog->buf, size);

    qlog->last = qlog->buf;
}


static ngx_int_t
ngx_quic_qlog_write(ngx_quic_qlog_t *qlog, u_char *buf, size_t size)
{
    /* if the output buffer belongs to a different qlog, flush it first */

    if (ngx_quic_qlog_out_owner != qlog) {
        if (ngx_quic_qlog_out_owner != NULL) {
            (void) ngx_quic_qlog_flush(ngx_quic_qlog_out_owner);
        }
        ngx_quic_qlog_out_owner = qlog;
    }

    /* fits in the remaining output buffer space */

    if (size <= (size_t) (ngx_quic_qlog_out_end - ngx_quic_qlog_out_last)) {
        ngx_quic_qlog_out_last = ngx_cpymem(ngx_quic_qlog_out_last, buf, size);
        return NGX_OK;
    }

    /* buffer is full, flush it */

    if (ngx_quic_qlog_flush(qlog) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_qlog_out_owner = qlog;

    /* event larger than the whole output buffer: write directly */

    if (size > (size_t) (ngx_quic_qlog_out_end - ngx_quic_qlog_out_buf)) {
        return ngx_quic_qlog_write_fd(qlog, buf, size);
    }

    ngx_quic_qlog_out_last = ngx_cpymem(ngx_quic_qlog_out_last, buf, size);
    return NGX_OK;
}


static ngx_int_t
ngx_quic_qlog_flush(ngx_quic_qlog_t *qlog)
{
    ngx_int_t  rc;

    if (ngx_quic_qlog_out_owner != qlog) {
        return NGX_OK;
    }

    rc = NGX_OK;

    if (ngx_quic_qlog_out_last > ngx_quic_qlog_out_buf) {
        rc = ngx_quic_qlog_write_fd(qlog, ngx_quic_qlog_out_buf,
                                    ngx_quic_qlog_out_last
                                    - ngx_quic_qlog_out_buf);
        ngx_quic_qlog_out_last = ngx_quic_qlog_out_buf;
    }

    ngx_quic_qlog_out_owner = NULL;

    return rc;
}


static ngx_int_t
ngx_quic_qlog_write_fd(ngx_quic_qlog_t *qlog, u_char *buf, size_t size)
{
    ssize_t  n;

    n = ngx_write_fd(qlog->fd, buf, size);

    if (n == -1) {
        ngx_log_error(NGX_LOG_WARN, qlog->log, ngx_errno,
                      ngx_write_fd_n " to \"%V\" failed", &qlog->path);
        ngx_close_file(qlog->fd);
        qlog->fd = NGX_INVALID_FILE;
        qlog->closed = 1;
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_WARN, qlog->log, 0,
                      ngx_write_fd_n " to \"%V\" was incomplete: %z of %uz",
                      &qlog->path, n, size);
        ngx_close_file(qlog->fd);
        qlog->fd = NGX_INVALID_FILE;
        qlog->closed = 1;
        return NGX_ERROR;
    }

    qlog->bytes_written += size;

    /* check whether writing the next event could exceed max_size */

    if (qlog->max_size
        && qlog->bytes_written + NGX_QUIC_QLOG_BUF_SIZE >= qlog->max_size)
    {
        ngx_log_error(NGX_LOG_INFO, qlog->log, 0,
                      "qlog max_size reached, closing \"%V\"", &qlog->path);
        ngx_close_file(qlog->fd);
        qlog->fd = NGX_INVALID_FILE;
        qlog->closed = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_qlog_init_worker_buffers(void)
{
    if (ngx_quic_qlog_buf != NULL && ngx_quic_qlog_out_buf != NULL) {
        return NGX_OK;
    }

    if (ngx_cycle == NULL || ngx_cycle->pool == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_qlog_buf == NULL) {
        ngx_quic_qlog_buf = ngx_palloc(ngx_cycle->pool,
                                           NGX_QUIC_QLOG_BUF_SIZE);
        if (ngx_quic_qlog_buf == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_quic_qlog_out_buf == NULL) {
        ngx_quic_qlog_out_buf = ngx_palloc(ngx_cycle->pool,
                                           NGX_QUIC_QLOG_OUT_BUF_SIZE);
        if (ngx_quic_qlog_out_buf == NULL) {
            return NGX_ERROR;
        }
    }

    ngx_quic_qlog_end = ngx_quic_qlog_buf + NGX_QUIC_QLOG_BUF_SIZE;
    ngx_quic_qlog_out_end = ngx_quic_qlog_out_buf + NGX_QUIC_QLOG_OUT_BUF_SIZE;
    ngx_quic_qlog_out_last = ngx_quic_qlog_out_buf;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_qlog_open(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    u_char     *p;
    ngx_str_t  *dir;
    ngx_str_t   file;

    dir = &qc->conf->qlog_path;

    if (dir->len == 0) {
        return NGX_ERROR;
    }

    if (qc->tp.original_dcid.len == 0) {
        return NGX_ERROR;
    }

    file.len = dir->len + 1 + qc->tp.original_dcid.len * 2 + sizeof(".sqlog");
    file.data = ngx_pnalloc(c->pool, file.len);
    if (file.data == NULL) {
        return NGX_ERROR;
    }

    p = file.data;

    p = ngx_cpymem(p, dir->data, dir->len);

    if (!ngx_path_separator(*(p - 1))) {
        *p++ = '/';
    } else {
        file.len--;
    }

    p = ngx_hex_dump(p, qc->tp.original_dcid.data, qc->tp.original_dcid.len);

    p = ngx_cpymem(p, ".sqlog", sizeof(".sqlog") - 1);
    *p = '\0';

    qc->qlog->fd = ngx_open_file(file.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                                 NGX_FILE_DEFAULT_ACCESS);

    if (qc->qlog->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &file);
        return NGX_ERROR;
    }

    qc->qlog->path = file;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_qlog_write_header(ngx_connection_t *c, ngx_quic_connection_t *qc,
    uint64_t reference_time_ms)
{
    u_char   *p, *end;

    p = qc->qlog->last;
    end = qc->qlog->end;

    ngx_qlog_write_literal(p, end, "\x1e{\"qlog_version\":\"0.3\","
                           "\"qlog_format\":\"JSON-SEQ\","
                           "\"trace\":{\"common_fields\":{");
    ngx_qlog_write_pair_hex(p, end, "group_id",
                            qc->tp.original_dcid.data,
                            qc->tp.original_dcid.len);
    ngx_qlog_write_literal(p, end, ",\"time_format\":\"relative\",");
    ngx_qlog_write_pair_num(p, end, "reference_time", reference_time_ms);
    ngx_qlog_write_literal(p, end, "},\"vantage_point\":{\"name\":\"nginx\","
                           "\"type\":\"server\"}}}\n");

    return ngx_quic_qlog_write(qc->qlog, qc->qlog->last, p - qc->qlog->last);
}


static ngx_quic_qlog_t *
ngx_quic_qlog_start_event(ngx_quic_qlog_t *qlog, u_char **pp, u_char **pend,
    ngx_uint_t min_importance, const char *name)
{
    if (qlog == NULL || qlog->closed || qlog->importance < min_importance) {
        return NULL;
    }

    *pp = qlog->last;
    *pend = qlog->end;
    ngx_qlog_write(*pp, *pend, "\x1e{\"time\":%uL,\"name\":\"%s\",\"data\":{",
                   (uint64_t) (ngx_current_msec - qlog->start_time), name);

    return qlog;
}


static const char *
ngx_quic_qlog_packet_name(uint8_t flags)
{
    if (ngx_quic_short_pkt(flags)) {
        return "1RTT";
    }

    switch (flags & NGX_QUIC_PKT_TYPE) {
    case NGX_QUIC_PKT_INITIAL:
        return "initial";
    case NGX_QUIC_PKT_ZRTT:
        return "0RTT";
    case NGX_QUIC_PKT_HANDSHAKE:
        return "handshake";
    case NGX_QUIC_PKT_RETRY:
        return "retry";
    default:
        return "unknown";
    }
}


static const char *
ngx_quic_qlog_packet_name_by_level(ngx_uint_t level)
{
    switch (level) {
    case NGX_QUIC_ENCRYPTION_INITIAL:
        return "initial";
    case NGX_QUIC_ENCRYPTION_HANDSHAKE:
        return "handshake";
    case NGX_QUIC_ENCRYPTION_APPLICATION:
        return "1RTT";
    default:
        return "unknown";
    }
}


static u_char *
ngx_quic_qlog_padding_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"padding\",");
    ngx_qlog_write_pair_num(p, end, "payload_length", f->len);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_ping_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"ping\"}");
    return p;
}


static u_char *
ngx_quic_qlog_ack_frame(u_char *p, u_char *end, ngx_quic_connection_t *qc,
    ngx_log_t *log, ngx_quic_frame_t *f)
{
    double                 ack_delay;
    u_char                *pos, *last;
    ssize_t                n;
    uint64_t               min, max, gap, range;
    ngx_uint_t             i, ack_delay_exponent;
    ngx_quic_ack_frame_t  *ack;

    ack = &f->u.ack;

    ack_delay_exponent = qc->qlog->sent ? qc->tp.ack_delay_exponent
                                        : qc->ctp.ack_delay_exponent;
    ack_delay = (double) (ack->delay << ack_delay_exponent) / 1000.0;

    ngx_qlog_write(p, end, "{\"frame_type\":\"ack\",\"ack_delay\":%.3f"
                   ",\"acked_ranges\":[", ack_delay);

    if (ack->first_range > ack->largest) {
        ngx_qlog_write_literal(p, end, "]}");
        return p;
    }

    min = ack->largest - ack->first_range;
    max = ack->largest;

    if (min == max) {
        ngx_qlog_write(p, end, "[%uL]", min);
    } else {
        ngx_qlog_write(p, end, "[%uL,%uL]", min, max);
    }

    if (f->data && f->data->buf) {
        pos  = f->data->buf->pos;
        last = f->data->buf->last;
    } else {
        pos = last = NULL;
    }

    for (i = 0; i < ack->range_count; i++) {

        n = ngx_quic_parse_ack_range(log, pos, last,
                                     &gap, &range);
        if (n == NGX_ERROR) {
            break;
        }
        pos += n;

        if (gap + 2 > min) {
            break;
        }

        max = min - gap - 2;

        if (range > max) {
            break;
        }

        min = max - range;

        if (min == max) {
            ngx_qlog_write(p, end, ",[%uL]", min);
        } else {
            ngx_qlog_write(p, end, ",[%uL,%uL]", min, max);
        }
    }

    ngx_qlog_write_char(p, end, ']');

    if (f->type == NGX_QUIC_FT_ACK_ECN) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ect1", ack->ect1);
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ect0", ack->ect0);
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ce", ack->ce);
    }

    ngx_qlog_write_char(p, end, '}');
    return p;
}


static u_char *
ngx_quic_qlog_reset_stream_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"reset_stream\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.reset_stream.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "error_code", f->u.reset_stream.error_code);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "final_size", f->u.reset_stream.final_size);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_stop_sending_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"stop_sending\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.stop_sending.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "error_code", f->u.stop_sending.error_code);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_crypto_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"crypto\",");
    ngx_qlog_write_pair_num(p, end, "offset", f->u.crypto.offset);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "length", f->u.crypto.length);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_new_token_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end,
                           "{\"frame_type\":\"new_token\",\"token\":{");
    ngx_qlog_write_pair_num(p, end, "length", f->u.token.length);
    ngx_qlog_write_char(p, end, '}');
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_stream_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"stream\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.stream.stream_id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "offset", f->u.stream.offset);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "length", f->u.stream.length);

    if (f->u.stream.fin) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_bool(p, end, "fin", 1);
    }
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_max_data_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"max_data\",");
    ngx_qlog_write_pair_num(p, end, "maximum", f->u.max_data.max_data);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_max_stream_data_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"max_stream_data\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.max_stream_data.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "maximum", f->u.max_stream_data.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_max_streams_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"max_streams\",");
    ngx_qlog_write_pair_num(p, end, "maximum", f->u.max_streams.limit);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "stream_type",
                            f->u.max_streams.bidi ? "bidirectional"
                                                  : "unidirectional");

    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_data_blocked_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"data_blocked\",");
    ngx_qlog_write_pair_num(p, end, "limit", f->u.data_blocked.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_stream_data_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"stream_data_blocked\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.stream_data_blocked.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "limit", f->u.stream_data_blocked.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_streams_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"streams_blocked\",");
    ngx_qlog_write_pair_str(p, end, "stream_type",
                            f->u.streams_blocked.bidi ? "bidirectional"
                                                      : "unidirectional");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "limit", f->u.streams_blocked.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_new_connection_id_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"new_connection_id\",");
    ngx_qlog_write_pair_num(p, end, "sequence_number", f->u.ncid.seqnum);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "retire_prior_to", f->u.ncid.retire);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "connection_id_length", f->u.ncid.len);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_hex(p, end, "connection_id", f->u.ncid.cid,
                            f->u.ncid.len);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_hex(p, end, "stateless_reset_token", f->u.ncid.srt,
                            NGX_QUIC_SR_TOKEN_LEN);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_retire_connection_id_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end,
                           "{\"frame_type\":\"retire_connection_id\",");
    ngx_qlog_write_pair_num(p, end, "sequence_number",
                            f->u.retire_cid.sequence_number);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_path_challenge_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"path_challenge\",");
    ngx_qlog_write_pair_hex(p, end, "data", f->u.path_challenge.data,
                            sizeof(f->u.path_challenge.data));
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_path_response_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"path_response\",");
    ngx_qlog_write_pair_hex(p, end, "data", f->u.path_response.data,
                            sizeof(f->u.path_response.data));
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_connection_close_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_uint_t  is_app;

    is_app = (f->type == NGX_QUIC_FT_CONNECTION_CLOSE_APP);

    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"connection_close\",");
    ngx_qlog_write_pair_str(p, end, "error_space", is_app ? "application"
                                                          : "transport");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "error_code", f->u.close.error_code);

    if (f->u.close.reason.len > 0) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_strv(p, end, "reason", &f->u.close.reason);
    }

    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_handshake_done_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"handshake_done\"}");
    return p;
}

#endif /* NGX_QUIC_QLOG */
