
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_MAX_ACK_GAP                 2

/* RFC 9002, 6.1.1. Packet Threshold: kPacketThreshold */
#define NGX_QUIC_PKT_THR                     3 /* packets */
/* RFC 9002, 6.1.2. Time Threshold: kGranularity */
#define NGX_QUIC_TIME_GRANULARITY            1 /* ms */

/* RFC 9002, 7.6.1. Duration: kPersistentCongestionThreshold */
#define NGX_QUIC_PERSISTENT_CONGESTION_THR   3

/* CUBIC parameters x10 */
#define NGX_QUIC_CUBIC_BETA                  7
#define NGX_QUIC_CUBIC_C                     4


/* send time of ACK'ed packets */
typedef struct {
    ngx_msec_t                               max_pn;
    ngx_msec_t                               oldest;
    ngx_msec_t                               newest;
} ngx_quic_ack_stat_t;


static ngx_inline ngx_msec_t ngx_quic_time_threshold(ngx_quic_connection_t *qc);
static uint64_t ngx_quic_packet_threshold(ngx_quic_send_ctx_t *ctx);
static void ngx_quic_rtt_sample(ngx_connection_t *c, ngx_quic_ack_frame_t *ack,
    ngx_uint_t level, ngx_msec_t send_time);
static ngx_int_t ngx_quic_handle_ack_frame_range(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t min, uint64_t max,
    ngx_quic_ack_stat_t *st);
static size_t ngx_quic_congestion_cubic(ngx_connection_t *c);
static void ngx_quic_drop_ack_ranges(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t pn);
static ngx_int_t ngx_quic_detect_lost(ngx_connection_t *c,
    ngx_quic_ack_stat_t *st);
static ngx_msec_t ngx_quic_congestion_cubic_time(ngx_connection_t *c);
static ngx_msec_t ngx_quic_pcg_duration(ngx_connection_t *c);
static void ngx_quic_persistent_congestion(ngx_connection_t *c);
static ngx_msec_t ngx_quic_oldest_sent_packet(ngx_connection_t *c);
static void ngx_quic_congestion_lost(ngx_connection_t *c,
    ngx_quic_frame_t *frame);
static void ngx_quic_lost_handler(ngx_event_t *ev);


/* RFC 9002, 6.1.2. Time Threshold: kTimeThreshold, kGranularity */
static ngx_inline ngx_msec_t
ngx_quic_time_threshold(ngx_quic_connection_t *qc)
{
    ngx_msec_t  thr;

    thr = ngx_max(qc->latest_rtt, qc->avg_rtt);
    thr += thr >> 3;

    return ngx_max(thr, NGX_QUIC_TIME_GRANULARITY);
}


static uint64_t
ngx_quic_packet_threshold(ngx_quic_send_ctx_t *ctx)
{
    uint64_t           pkt_thr;
    ngx_queue_t       *q;
    ngx_quic_frame_t  *f;

    if (ngx_queue_empty(&ctx->sent)) {
        return NGX_QUIC_PKT_THR;
    }

    q = ngx_queue_head(&ctx->sent);
    f = ngx_queue_data(q, ngx_quic_frame_t, queue);
    pkt_thr = (ctx->pnum - f->pnum) / 2;

    if (pkt_thr <= NGX_QUIC_PKT_THR) {
        return NGX_QUIC_PKT_THR;
    }

    return pkt_thr;
}


ngx_int_t
ngx_quic_handle_ack_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *f)
{
    ssize_t                 n;
    u_char                 *pos, *end;
    uint64_t                min, max, gap, range;
    ngx_uint_t              i;
    ngx_quic_ack_stat_t     send_time;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_ack_frame_t   *ack;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_handle_ack_frame level:%ui", pkt->level);

    ack = &f->u.ack;

    /*
     * RFC 9000, 19.3.1.  ACK Ranges
     *
     *  If any computed packet number is negative, an endpoint MUST
     *  generate a connection error of type FRAME_ENCODING_ERROR.
     */

    if (ack->first_range > ack->largest) {
        qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic invalid first range in ack frame");
        return NGX_ERROR;
    }

    min = ack->largest - ack->first_range;
    max = ack->largest;

    send_time.oldest = NGX_TIMER_INFINITE;
    send_time.newest = NGX_TIMER_INFINITE;

    if (ngx_quic_handle_ack_frame_range(c, ctx, min, max, &send_time)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* RFC 9000, 13.2.4.  Limiting Ranges by Tracking ACK Frames */
    if (ctx->largest_ack < max || ctx->largest_ack == NGX_QUIC_UNSET_PN) {
        ctx->largest_ack = max;
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic updated largest received ack:%uL", max);

        /*
         * RFC 9002, 5.1.  Generating RTT Samples
         *
         *  An endpoint generates an RTT sample on receiving an
         *  ACK frame that meets the following two conditions:
         *
         *  - the largest acknowledged packet number is newly acknowledged
         *  - at least one of the newly acknowledged packets was ack-eliciting.
         */

        if (send_time.max_pn != NGX_TIMER_INFINITE) {
            ngx_quic_rtt_sample(c, ack, pkt->level, send_time.max_pn);
        }
    }

    if (f->data) {
        pos = f->data->buf->pos;
        end = f->data->buf->last;

    } else {
        pos = NULL;
        end = NULL;
    }

    for (i = 0; i < ack->range_count; i++) {

        n = ngx_quic_parse_ack_range(pkt->log, pos, end, &gap, &range);
        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
        pos += n;

        if (gap + 2 > min) {
            qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic invalid range:%ui in ack frame", i);
            return NGX_ERROR;
        }

        max = min - gap - 2;

        if (range > max) {
            qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic invalid range:%ui in ack frame", i);
            return NGX_ERROR;
        }

        min = max - range;

        if (ngx_quic_handle_ack_frame_range(c, ctx, min, max, &send_time)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return ngx_quic_detect_lost(c, &send_time);
}


static void
ngx_quic_rtt_sample(ngx_connection_t *c, ngx_quic_ack_frame_t *ack,
    ngx_uint_t level, ngx_msec_t send_time)
{
    ngx_msec_t              latest_rtt, ack_delay, adjusted_rtt, rttvar_sample;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    latest_rtt = ngx_current_msec - send_time;
    qc->latest_rtt = latest_rtt;

    if (qc->min_rtt == NGX_TIMER_INFINITE) {
        qc->min_rtt = latest_rtt;
        qc->avg_rtt = latest_rtt;
        qc->rttvar = latest_rtt / 2;
        qc->first_rtt = ngx_current_msec;

    } else {
        qc->min_rtt = ngx_min(qc->min_rtt, latest_rtt);

        ack_delay = (ack->delay << qc->ctp.ack_delay_exponent) / 1000;

        if (c->ssl->handshaked) {
            ack_delay = ngx_min(ack_delay, qc->ctp.max_ack_delay);
        }

        adjusted_rtt = latest_rtt;

        if (qc->min_rtt + ack_delay < latest_rtt) {
            adjusted_rtt -= ack_delay;
        }

        rttvar_sample = ngx_abs((ngx_msec_int_t) (qc->avg_rtt - adjusted_rtt));
        qc->rttvar += (rttvar_sample >> 2) - (qc->rttvar >> 2);
        qc->avg_rtt += (adjusted_rtt >> 3) - (qc->avg_rtt >> 3);
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic rtt sample latest:%M min:%M avg:%M var:%M",
                   latest_rtt, qc->min_rtt, qc->avg_rtt, qc->rttvar);
}


static ngx_int_t
ngx_quic_handle_ack_frame_range(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t min, uint64_t max, ngx_quic_ack_stat_t *st)
{
    ngx_uint_t              found;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (ctx->level == NGX_QUIC_ENCRYPTION_APPLICATION) {
        if (ngx_quic_handle_path_mtu(c, qc->path, min, max) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    st->max_pn = NGX_TIMER_INFINITE;
    found = 0;

    q = ngx_queue_head(&ctx->sent);

    while (q != ngx_queue_sentinel(&ctx->sent)) {

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        q = ngx_queue_next(q);

        if (f->pnum > max) {
            break;
        }

        if (f->pnum >= min) {
            ngx_quic_congestion_ack(c, f);

            switch (f->type) {
            case NGX_QUIC_FT_ACK:
            case NGX_QUIC_FT_ACK_ECN:
                ngx_quic_drop_ack_ranges(c, ctx, f->u.ack.largest);
                break;

            case NGX_QUIC_FT_STREAM:
            case NGX_QUIC_FT_RESET_STREAM:
                ngx_quic_handle_stream_ack(c, f);
                break;
            }

            if (f->pnum == max) {
                st->max_pn = f->send_time;
            }

            /* save earliest and latest send times of frames ack'ed */
            if (st->oldest == NGX_TIMER_INFINITE || f->send_time < st->oldest) {
                st->oldest = f->send_time;
            }

            if (st->newest == NGX_TIMER_INFINITE || f->send_time > st->newest) {
                st->newest = f->send_time;
            }

            ngx_queue_remove(&f->queue);
            ngx_quic_free_frame(c, f);
            found = 1;
        }
    }

    if (!found) {

        if (max < ctx->pnum) {
            /* duplicate ACK or ACK for non-ack-eliciting frame */
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic ACK for the packet not sent");

        qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_ftype = NGX_QUIC_FT_ACK;
        qc->error_reason = "unknown packet number";

        return NGX_ERROR;
    }

    if (!qc->push.timer_set) {
        ngx_post_event(&qc->push, &ngx_posted_events);
    }

    qc->pto_count = 0;

    return NGX_OK;
}


void
ngx_quic_congestion_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    size_t                  w_cubic;
    ngx_uint_t              blocked;
    ngx_msec_t              now, timer;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    if (f->plen == 0) {
        return;
    }

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    if (f->pnum < qc->rst_pnum) {
        return;
    }

    now = ngx_current_msec;

    blocked = (cg->in_flight >= cg->window) ? 1 : 0;

    cg->in_flight -= f->plen;

    /* prevent recovery_start from wrapping */

    timer = now - cg->recovery_start;

    if ((ngx_msec_int_t) timer < 0) {
        cg->recovery_start = ngx_quic_oldest_sent_packet(c) - 1;
    }

    timer = f->send_time - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack rec t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

    if (cg->idle) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack idle t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

    if (cg->window < cg->ssthresh) {
        cg->window += f->plen;

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack ss t:%M win:%uz ss:%z if:%uz",
                       now, cg->window, cg->ssthresh, cg->in_flight);

    } else {

        /* RFC 9438, 4.2. Window Increase Function */

        w_cubic = ngx_quic_congestion_cubic(c);

        if (cg->window < cg->w_prior) {
            cg->w_est += (uint64_t) cg->mtu * f->plen
                         * 3 * (10 - NGX_QUIC_CUBIC_BETA)
                         / (10 + NGX_QUIC_CUBIC_BETA) / cg->window;

        } else {
            cg->w_est += (uint64_t) cg->mtu * f->plen / cg->window;
        }

        if (w_cubic < cg->w_est) {
            cg->window = cg->w_est;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack reno t:%M win:%uz c:%uz if:%uz",
                       now, cg->window, w_cubic, cg->in_flight);

        } else if (w_cubic > cg->window) {

            if (w_cubic >= cg->window * 3 / 2) {
                cg->window += cg->mtu / 2;

            } else {
                cg->window += (uint64_t) cg->mtu * (w_cubic - cg->window)
                              / cg->window;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                          "quic congestion ack cubic t:%M win:%uz c:%uz if:%uz",
                          now, cg->window, w_cubic, cg->in_flight);

        } else {
            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic congestion ack skip t:%M win:%uz c:%uz if:%uz",
                           now, cg->window, w_cubic, cg->in_flight);
        }
    }

done:

    if (blocked && cg->in_flight < cg->window) {
        ngx_post_event(&qc->push, &ngx_posted_events);
    }
}


static size_t
ngx_quic_congestion_cubic(ngx_connection_t *c)
{
    int64_t                 w, t, cc;
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    ngx_quic_congestion_idle(c, cg->idle);

    now = ngx_current_msec;
    t = (ngx_msec_int_t) (now - cg->k);

    if (t > 1000000) {
        w = NGX_MAX_SIZE_T_VALUE;
        goto done;
    }

    if (t < -1000000) {
        w = 0;
        goto done;
    }

    /*
     * RFC 9438, Figure 1
     *
     *   w_cubic = C * (t_msec / 1000) ^ 3 * mtu + w_max
     */

    cc = 10000000000ll / (int64_t) cg->mtu / NGX_QUIC_CUBIC_C;
    w = t * t * t / cc + (int64_t) cg->w_max;

    if (w > NGX_MAX_SIZE_T_VALUE) {
        w = NGX_MAX_SIZE_T_VALUE;
    }

    if (w < 0) {
        w = 0;
    }

done:

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic cubic t:%L w:%L wm:%uz", t, w, cg->w_max);

    return w;
}


void
ngx_quic_congestion_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion idle:%ui", idle);

    if (cg->window >= cg->ssthresh) {
        /* RFC 9438, 5.8. Behavior for Application-Limited Flows */

        now = ngx_current_msec;

        if (cg->idle) {
            cg->k += now - cg->idle_start;
        }

        cg->idle_start = now;
    }

    cg->idle = idle;
}


static void
ngx_quic_drop_ack_ranges(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t pn)
{
    uint64_t               base;
    ngx_uint_t             i, smallest, largest;
    ngx_quic_ack_range_t  *r;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_drop_ack_ranges pn:%uL largest:%uL"
                   " fr:%uL nranges:%ui", pn, ctx->largest_range,
                   ctx->first_range, ctx->nranges);

    base = ctx->largest_range;

    if (base == NGX_QUIC_UNSET_PN) {
        return;
    }

    if (ctx->pending_ack != NGX_QUIC_UNSET_PN && pn >= ctx->pending_ack) {
        ctx->pending_ack = NGX_QUIC_UNSET_PN;
    }

    largest = base;
    smallest = largest - ctx->first_range;

    if (pn >= largest) {
        ctx->largest_range = NGX_QUIC_UNSET_PN;
        ctx->first_range = 0;
        ctx->nranges = 0;
        return;
    }

    if (pn >= smallest) {
        ctx->first_range = largest - pn - 1;
        ctx->nranges = 0;
        return;
    }

    for (i = 0; i < ctx->nranges; i++) {
        r = &ctx->ranges[i];

        largest = smallest - r->gap - 2;
        smallest = largest - r->range;

        if (pn >= largest) {
            ctx->nranges = i;
            return;
        }
        if (pn >= smallest) {
            r->range = largest - pn - 1;
            ctx->nranges = i + 1;
            return;
        }
    }
}


static ngx_int_t
ngx_quic_detect_lost(ngx_connection_t *c, ngx_quic_ack_stat_t *st)
{
    uint64_t                pkt_thr;
    ngx_uint_t              i, nlost;
    ngx_msec_t              now, wait, thr, oldest, newest;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *start;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    now = ngx_current_msec;
    thr = ngx_quic_time_threshold(qc);

#if (NGX_SUPPRESS_WARN)
    oldest = now;
    newest = now;
#endif

    nlost = 0;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ctx->largest_ack == NGX_QUIC_UNSET_PN) {
            continue;
        }

        pkt_thr = ngx_quic_packet_threshold(ctx);

        while (!ngx_queue_empty(&ctx->sent)) {

            q = ngx_queue_head(&ctx->sent);
            start = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if (start->pnum > ctx->largest_ack) {
                break;
            }

            wait = start->send_time + thr - now;

            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "quic detect_lost pnum:%uL thr:%M pthr:%uL wait:%i level:%ui",
                  start->pnum, thr, pkt_thr, (ngx_int_t) wait, start->level);

            if ((ngx_msec_int_t) wait > 0
                && ctx->largest_ack - start->pnum < pkt_thr)
            {
                break;
            }

            if ((ngx_msec_int_t) (start->send_time - qc->first_rtt) > 0) {

                if (nlost == 0
                    || (ngx_msec_int_t) (start->send_time - oldest) < 0)
                {
                    oldest = start->send_time;
                }

                if (nlost == 0
                    || (ngx_msec_int_t) (start->send_time - newest) > 0)
                {
                    newest = start->send_time;
                }

                nlost++;
            }

            ngx_quic_resend_frames(c, ctx);
        }
    }


    /* RFC 9002, 7.6.2.  Establishing Persistent Congestion */

    /*
     * Once acknowledged, packets are no longer tracked. Thus no send time
     * information is available for such packets. This limits persistent
     * congestion algorithm to packets mentioned within ACK ranges of the
     * latest ACK frame.
     */

    if (st && nlost >= 2 && ((ngx_msec_int_t) (st->newest - oldest) < 0
                             || (ngx_msec_int_t) (st->oldest - newest) > 0))
    {
        if (newest - oldest > ngx_quic_pcg_duration(c)) {
            ngx_quic_persistent_congestion(c);
        }
    }

    ngx_quic_set_lost_timer(c);

    return NGX_OK;
}


static ngx_msec_t
ngx_quic_pcg_duration(ngx_connection_t *c)
{
    ngx_msec_t              duration;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    duration = qc->avg_rtt;
    duration += ngx_max(4 * qc->rttvar, NGX_QUIC_TIME_GRANULARITY);
    duration += qc->ctp.max_ack_delay;
    duration *= NGX_QUIC_PERSISTENT_CONGESTION_THR;

    return duration;
}


static void
ngx_quic_persistent_congestion(ngx_connection_t *c)
{
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    cg->mtu = qc->path->mtu;
    cg->recovery_start = ngx_quic_oldest_sent_packet(c) - 1;
    cg->window = cg->mtu * 2;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion persistent t:%M win:%uz",
                   ngx_current_msec, cg->window);
}


static ngx_msec_t
ngx_quic_oldest_sent_packet(ngx_connection_t *c)
{
    ngx_msec_t              oldest;
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *start;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    oldest = ngx_current_msec;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (!ngx_queue_empty(&ctx->sent)) {
            q = ngx_queue_head(&ctx->sent);
            start = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if ((ngx_msec_int_t) (start->send_time - oldest) < 0) {
                oldest = start->send_time;
            }
        }
    }

    return oldest;
}


void
ngx_quic_resend_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    uint64_t                pnum;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    q = ngx_queue_head(&ctx->sent);
    start = ngx_queue_data(q, ngx_quic_frame_t, queue);
    pnum = start->pnum;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic resend packet pnum:%uL", start->pnum);

    ngx_quic_congestion_lost(c, start);

    do {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->pnum != pnum) {
            break;
        }

        q = ngx_queue_next(q);

        ngx_queue_remove(&f->queue);

        switch (f->type) {
        case NGX_QUIC_FT_ACK:
        case NGX_QUIC_FT_ACK_ECN:
            if (ctx->level == NGX_QUIC_ENCRYPTION_APPLICATION) {
                /* force generation of most recent acknowledgment */
                ctx->send_ack = NGX_QUIC_MAX_ACK_GAP;
            }

            ngx_quic_free_frame(c, f);
            break;

        case NGX_QUIC_FT_PING:
        case NGX_QUIC_FT_PATH_CHALLENGE:
        case NGX_QUIC_FT_PATH_RESPONSE:
        case NGX_QUIC_FT_CONNECTION_CLOSE:
            ngx_quic_free_frame(c, f);
            break;

        case NGX_QUIC_FT_MAX_DATA:
            f->u.max_data.max_data = qc->streams.recv_max_data;
            ngx_quic_queue_frame(qc, f);
            break;

        case NGX_QUIC_FT_MAX_STREAMS:
        case NGX_QUIC_FT_MAX_STREAMS2:
            f->u.max_streams.limit = f->u.max_streams.bidi
                                     ? qc->streams.remote_max_streams_bidi
                                     : qc->streams.remote_max_streams_uni;
            ngx_quic_queue_frame(qc, f);
            break;

        case NGX_QUIC_FT_MAX_STREAM_DATA:
            qs = ngx_quic_find_stream(&qc->streams.tree,
                                      f->u.max_stream_data.id);
            if (qs == NULL) {
                ngx_quic_free_frame(c, f);
                break;
            }

            f->u.max_stream_data.limit = qs->recv_max_data;
            ngx_quic_queue_frame(qc, f);
            break;

        case NGX_QUIC_FT_STREAM:
            qs = ngx_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);

            if (qs == NULL
                || qs->send_state == NGX_QUIC_STREAM_SEND_RESET_SENT
                || qs->send_state == NGX_QUIC_STREAM_SEND_RESET_RECVD)
            {
                ngx_quic_free_frame(c, f);
                break;
            }

            /* fall through */

        default:
            ngx_queue_insert_tail(&ctx->frames, &f->queue);
        }

    } while (q != ngx_queue_sentinel(&ctx->sent));

    if (qc->closing) {
        return;
    }

    ngx_post_event(&qc->push, &ngx_posted_events);
}


static void
ngx_quic_congestion_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_uint_t              blocked;
    ngx_msec_t              now, timer;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    if (f->plen == 0) {
        return;
    }

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    if (f->pnum < qc->rst_pnum) {
        return;
    }

    blocked = (cg->in_flight >= cg->window) ? 1 : 0;

    cg->in_flight -= f->plen;
    f->plen = 0;

    timer = f->send_time - cg->recovery_start;

    now = ngx_current_msec;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion lost rec t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

    if (f->ignore_loss) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion lost ignore t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

    /* RFC 9438, 4.6. Multiplicative Decrease */

    cg->mtu = qc->path->mtu;
    cg->recovery_start = now;
    cg->w_prior = cg->window;
    /* RFC 9438, 4.7. Fast Convergence */
    cg->w_max = (cg->window < cg->w_max)
                ? cg->window * (10 + NGX_QUIC_CUBIC_BETA) / 20 : cg->window;
    cg->ssthresh = cg->in_flight * NGX_QUIC_CUBIC_BETA / 10;
    cg->window = ngx_max(cg->ssthresh, cg->mtu * 2);
    cg->w_est = cg->window;
    cg->k = now + ngx_quic_congestion_cubic_time(c);
    cg->idle_start = now;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion lost t:%M win:%uz if:%uz",
                   now, cg->window, cg->in_flight);

done:

    if (blocked && cg->in_flight < cg->window) {
        ngx_post_event(&qc->push, &ngx_posted_events);
    }
}


static ngx_msec_t
ngx_quic_congestion_cubic_time(ngx_connection_t *c)
{
    int64_t                 v, x, d, cc;
    ngx_uint_t              n;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    /*
     * RFC 9438, Figure 2
     *
     *   k_msec = ((w_max - cwnd_epoch) / C / mtu) ^ 1/3 * 1000
     */

    if (cg->w_max <= cg->window) {
        return 0;
    }

    cc = 10000000000ll / (int64_t) cg->mtu / NGX_QUIC_CUBIC_C;
    v = (int64_t) (cg->w_max - cg->window) * cc;

    /*
     * Newton-Raphson method for x ^ 3 = v:
     *
     *   x_next = (2 * x_prev + v / x_prev ^ 2) / 3
     */

    x = 5000;

    for (n = 1; n <= 10; n++) {
        d =  (v / x / x - x) / 3;
        x += d;

        if (ngx_abs(d) <= 100) {
            break;
        }
    }

    if (x > NGX_MAX_SIZE_T_VALUE) {
        return NGX_MAX_SIZE_T_VALUE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic cubic time:%L n:%ui", x, n);

    return x;
}


void
ngx_quic_set_lost_timer(ngx_connection_t *c)
{
    uint64_t                pkt_thr;
    ngx_uint_t              i;
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_msec_int_t          lost, pto, w;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    now = ngx_current_msec;

    lost = -1;
    pto = -1;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (ngx_queue_empty(&ctx->sent)) {
            continue;
        }

        if (ctx->largest_ack != NGX_QUIC_UNSET_PN) {
            q = ngx_queue_head(&ctx->sent);
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);
            w = (ngx_msec_int_t)
                            (f->send_time + ngx_quic_time_threshold(qc) - now);

            if (f->pnum <= ctx->largest_ack) {
                pkt_thr = ngx_quic_packet_threshold(ctx);

                if (w < 0 || ctx->largest_ack - f->pnum >= pkt_thr) {
                    w = 0;
                }

                if (lost == -1 || w < lost) {
                    lost = w;
                }
            }
        }

        q = ngx_queue_last(&ctx->sent);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        w = (ngx_msec_int_t)
                (f->send_time + (ngx_quic_pto(c, ctx) << qc->pto_count) - now);

        if (w < 0) {
            w = 0;
        }

        if (pto == -1 || w < pto) {
            pto = w;
        }
    }

    if (qc->pto.timer_set) {
        ngx_del_timer(&qc->pto);
    }

    if (lost != -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic lost timer lost:%M", lost);

        qc->pto.handler = ngx_quic_lost_handler;
        ngx_add_timer(&qc->pto, lost);
        return;
    }

    if (pto != -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic lost timer pto:%M", pto);

        qc->pto.handler = ngx_quic_pto_handler;
        ngx_add_timer(&qc->pto, pto);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic lost timer unset");
}


ngx_msec_t
ngx_quic_pto(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    ngx_msec_t              duration;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /* RFC 9002, Appendix A.8.  Setting the Loss Detection Timer */

    duration = qc->avg_rtt;
    duration += ngx_max(4 * qc->rttvar, NGX_QUIC_TIME_GRANULARITY);

    if (ctx->level == NGX_QUIC_ENCRYPTION_APPLICATION && c->ssl->handshaked) {
        duration += qc->ctp.max_ack_delay;
    }

    return duration;
}


static
void ngx_quic_lost_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic lost timer");

    c = ev->data;

    if (ngx_quic_detect_lost(c, NULL) != NGX_OK) {
        ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR, "lost detect error");
    }

    ngx_quic_end_handler(c);
}


void
ngx_quic_pto_handler(ngx_event_t *ev)
{
    ngx_uint_t              i, n;
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_msec_int_t          w;
    ngx_connection_t       *c;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    c = ev->data;
    qc = ngx_quic_get_connection(c);
    now = ngx_current_msec;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic pto timer");

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ngx_queue_empty(&ctx->sent)) {
            continue;
        }

        q = ngx_queue_last(&ctx->sent);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        w = (ngx_msec_int_t)
                (f->send_time + (ngx_quic_pto(c, ctx) << qc->pto_count) - now);

        if (f->pnum <= ctx->largest_ack
            && ctx->largest_ack != NGX_QUIC_UNSET_PN)
        {
            continue;
        }

        if (w > 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic pto %s pto_count:%ui",
                       ngx_quic_level_name(ctx->level), qc->pto_count);

        for (n = 0; n < 2; n++) {

            f = ngx_quic_alloc_frame(c);
            if (f == NULL) {
                ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR,
                                   "memory error");
                goto done;
            }

            f->level = ctx->level;
            f->type = NGX_QUIC_FT_PING;
            f->ignore_congestion = 1;

            if (ngx_quic_frame_sendto(c, f, 0, qc->path) == NGX_ERROR) {
                ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR,
                                   "send error");
                goto done;
            }
        }
    }

    qc->pto_count++;

    ngx_quic_set_lost_timer(c);

done:

    ngx_quic_end_handler(c);
}


ngx_int_t
ngx_quic_ack_packet(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    uint64_t                base, largest, smallest, gs, ge, gap, range, pn;
    uint64_t                prev_pending;
    ngx_uint_t              i, nr;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_ack_range_t   *r;
    ngx_quic_connection_t  *qc;

    c->log->action = "preparing ack";

    qc = ngx_quic_get_connection(c);

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_ack_packet pn:%uL largest %L fr:%uL"
                   " nranges:%ui", pkt->pn, (int64_t) ctx->largest_range,
                   ctx->first_range, ctx->nranges);

    if (!ngx_quic_keys_available(qc->keys, ctx->level, 1)) {
        return NGX_OK;
    }

    prev_pending = ctx->pending_ack;

    if (pkt->need_ack) {

        ngx_post_event(&qc->push, &ngx_posted_events);

        if (ctx->send_ack == 0) {
            ctx->ack_delay_start = ngx_current_msec;
        }

        ctx->send_ack++;

        if (ctx->pending_ack == NGX_QUIC_UNSET_PN
            || ctx->pending_ack < pkt->pn)
        {
            ctx->pending_ack = pkt->pn;
        }
    }

    base = ctx->largest_range;
    pn = pkt->pn;

    if (base == NGX_QUIC_UNSET_PN) {
        ctx->largest_range = pn;
        ctx->largest_received = pkt->received;
        return NGX_OK;
    }

    if (base == pn) {
        return NGX_OK;
    }

    largest = base;
    smallest = largest - ctx->first_range;

    if (pn > base) {

        if (pn - base == 1) {
            ctx->first_range++;
            ctx->largest_range = pn;
            ctx->largest_received = pkt->received;

            return NGX_OK;

        } else {
            /* new gap in front of current largest */

            /* no place for new range, send current range as is */
            if (ctx->nranges == NGX_QUIC_MAX_RANGES) {

                if (prev_pending != NGX_QUIC_UNSET_PN) {
                    if (ngx_quic_send_ack(c, ctx) != NGX_OK) {
                        return NGX_ERROR;
                    }
                }

                if (prev_pending == ctx->pending_ack || !pkt->need_ack) {
                    ctx->pending_ack = NGX_QUIC_UNSET_PN;
                }
            }

            gap = pn - base - 2;
            range = ctx->first_range;

            ctx->first_range = 0;
            ctx->largest_range = pn;
            ctx->largest_received = pkt->received;

            /* packet is out of order, force send */
            if (pkt->need_ack) {
                ctx->send_ack = NGX_QUIC_MAX_ACK_GAP;
            }

            i = 0;

            goto insert;
        }
    }

    /*  pn < base, perform lookup in existing ranges */

    /* packet is out of order */
    if (pkt->need_ack) {
        ctx->send_ack = NGX_QUIC_MAX_ACK_GAP;
    }

    if (pn >= smallest && pn <= largest) {
        return NGX_OK;
    }

#if (NGX_SUPPRESS_WARN)
    r = NULL;
#endif

    for (i = 0; i < ctx->nranges; i++) {
        r = &ctx->ranges[i];

        ge = smallest - 1;
        gs = ge - r->gap;

        if (pn >= gs && pn <= ge) {

            if (gs == ge) {
                /* gap size is exactly one packet, now filled */

                /* data moves to previous range, current is removed */

                if (i == 0) {
                    ctx->first_range += r->range + 2;

                } else {
                    ctx->ranges[i - 1].range += r->range + 2;
                }

                nr = ctx->nranges - i - 1;
                if (nr) {
                    ngx_memmove(&ctx->ranges[i], &ctx->ranges[i + 1],
                                sizeof(ngx_quic_ack_range_t) * nr);
                }

                ctx->nranges--;

            } else if (pn == gs) {
                /* current gap shrinks from tail (current range grows) */
                r->gap--;
                r->range++;

            } else if (pn == ge) {
                /* current gap shrinks from head (previous range grows) */
                r->gap--;

                if (i == 0) {
                    ctx->first_range++;

                } else {
                    ctx->ranges[i - 1].range++;
                }

            } else {
                /* current gap is split into two parts */

                gap = ge - pn - 1;
                range = 0;

                if (ctx->nranges == NGX_QUIC_MAX_RANGES) {
                    if (prev_pending != NGX_QUIC_UNSET_PN) {
                        if (ngx_quic_send_ack(c, ctx) != NGX_OK) {
                            return NGX_ERROR;
                        }
                    }

                    if (prev_pending == ctx->pending_ack || !pkt->need_ack) {
                        ctx->pending_ack = NGX_QUIC_UNSET_PN;
                    }
                }

                r->gap = pn - gs - 1;
                goto insert;
            }

            return NGX_OK;
        }

        largest = smallest - r->gap - 2;
        smallest = largest - r->range;

        if (pn >= smallest && pn <= largest) {
            /* this packet number is already known */
            return NGX_OK;
        }

    }

    if (pn == smallest - 1) {
        /* extend first or last range */

        if (i == 0) {
            ctx->first_range++;

        } else {
            r->range++;
        }

        return NGX_OK;
    }

    /* nothing found, add new range at the tail  */

    if (ctx->nranges == NGX_QUIC_MAX_RANGES) {
        /* packet is too old to keep it */

        if (pkt->need_ack) {
            return ngx_quic_send_ack_range(c, ctx, pn, pn);
        }

        return NGX_OK;
    }

    gap = smallest - 2 - pn;
    range = 0;

insert:

    if (ctx->nranges < NGX_QUIC_MAX_RANGES) {
        ctx->nranges++;
    }

    ngx_memmove(&ctx->ranges[i + 1], &ctx->ranges[i],
                sizeof(ngx_quic_ack_range_t) * (ctx->nranges - i - 1));

    ctx->ranges[i].gap = gap;
    ctx->ranges[i].range = range;

    return NGX_OK;
}


ngx_int_t
ngx_quic_generate_ack(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    ngx_msec_t              delay;
    ngx_quic_connection_t  *qc;

    if (!ctx->send_ack) {
        return NGX_OK;
    }

    if (ctx->level == NGX_QUIC_ENCRYPTION_APPLICATION) {

        delay = ngx_current_msec - ctx->ack_delay_start;
        qc = ngx_quic_get_connection(c);

        if (ngx_queue_empty(&ctx->frames)
            && ctx->send_ack < NGX_QUIC_MAX_ACK_GAP
            && delay < qc->tp.max_ack_delay)
        {
            if (!qc->push.timer_set && !qc->closing) {
                ngx_add_timer(&qc->push,
                              qc->tp.max_ack_delay - delay);
            }

            return NGX_OK;
        }
    }

    if (ngx_quic_send_ack(c, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->send_ack = 0;

    return NGX_OK;
}
