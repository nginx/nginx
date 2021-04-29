
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_MAX_SHORT_HEADER        25 /* 1 flags + 20 dcid + 4 pn */
#define NGX_QUIC_MAX_LONG_HEADER         56
    /* 1 flags + 4 version + 2 x (1 + 20) s/dcid + 4 pn + 4 len + token len */

#define NGX_QUIC_MAX_UDP_PAYLOAD_OUT   1252
#define NGX_QUIC_MAX_UDP_PAYLOAD_OUT6  1232

#define NGX_QUIC_RETRY_TOKEN_LIFETIME     3 /* seconds */
#define NGX_QUIC_NEW_TOKEN_LIFETIME     600 /* seconds */
#define NGX_QUIC_RETRY_BUFFER_SIZE      256
    /* 1 flags + 4 version + 3 x (1 + 20) s/o/dcid + itag + token(64) */

/*
 * Endpoints MUST discard packets that are too small to be valid QUIC
 * packets.  With the set of AEAD functions defined in [QUIC-TLS],
 * packets that are smaller than 21 bytes are never valid.
 */
#define NGX_QUIC_MIN_PKT_LEN             21

#define NGX_QUIC_MIN_SR_PACKET           43 /* 5 rand + 16 srt + 22 padding */
#define NGX_QUIC_MAX_SR_PACKET         1200

#define NGX_QUIC_CC_MIN_INTERVAL       1000 /* 1s */


static ngx_int_t ngx_quic_socket_output(ngx_connection_t *c,
    ngx_quic_socket_t *qsock);
static ssize_t ngx_quic_output_packet(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, u_char *data, size_t max, size_t min,
    ngx_quic_socket_t *qsock);
static ngx_uint_t ngx_quic_get_padding_level(ngx_connection_t *c);
static ssize_t ngx_quic_send(ngx_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen);
static void ngx_quic_set_packet_number(ngx_quic_header_t *pkt,
    ngx_quic_send_ctx_t *ctx);


size_t
ngx_quic_max_udp_payload(ngx_connection_t *c)
{
    /* TODO: path MTU discovery */

#if (NGX_HAVE_INET6)
    if (c->sockaddr->sa_family == AF_INET6) {
        return NGX_QUIC_MAX_UDP_PAYLOAD_OUT6;
    }
#endif

    return NGX_QUIC_MAX_UDP_PAYLOAD_OUT;
}


ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (ngx_quic_socket_output(c, qc->socket) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_set_lost_timer(c);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_socket_output(ngx_connection_t *c, ngx_quic_socket_t *qsock)
{
    off_t                   max;
    size_t                  len, min, in_flight;
    ssize_t                 n;
    u_char                 *p;
    ngx_uint_t              i, pad;
    ngx_quic_path_t        *path;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;
    static u_char           dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "sending frames";

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    in_flight = cg->in_flight;

    path = qsock->path;

    for ( ;; ) {
        p = dst;

        len = ngx_min(qc->ctp.max_udp_payload_size,
                      NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

        if (path->state != NGX_QUIC_PATH_VALIDATED) {
            max = path->received * 3;
            max = (path->sent >= max) ? 0 : max - path->sent;

            len = ngx_min(len, (size_t) max);
        }

        pad = ngx_quic_get_padding_level(c);

        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

            ctx = &qc->send_ctx[i];

            if (ngx_quic_generate_ack(c, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            min = (i == pad && p - dst < NGX_QUIC_MIN_INITIAL_SIZE)
                  ? NGX_QUIC_MIN_INITIAL_SIZE - (p - dst) : 0;

            n = ngx_quic_output_packet(c, ctx, p, len, min, qsock);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            p += n;
            len -= n;
        }

        len = p - dst;
        if (len == 0) {
            break;
        }

        n = ngx_quic_send(c, dst, len, path->sockaddr, path->socklen);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        path->sent += len;
    }

    if (in_flight != cg->in_flight && !qc->send_timer_set && !qc->closing) {
        qc->send_timer_set = 1;
        ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    }


    return NGX_OK;
}


static ngx_uint_t
ngx_quic_get_padding_level(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    /*
     * 14.1.  Initial Datagram Size
     *
     * Similarly, a server MUST expand the payload of all UDP datagrams
     * carrying ack-eliciting Initial packets to at least the smallest
     * allowed maximum datagram size of 1200 bytes
     */

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_initial);

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->need_ack) {
            ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_handshake);

            if (ngx_queue_empty(&ctx->frames)) {
                return 0;
            }

            return 1;
        }
    }

    return NGX_QUIC_SEND_CTX_LAST;
}


static ssize_t
ngx_quic_output_packet(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    u_char *data, size_t max, size_t min, ngx_quic_socket_t *qsock)
{
    size_t                  len, hlen, pad_len;
    u_char                 *p;
    ssize_t                 flen;
    ngx_str_t               out, res;
    ngx_int_t               rc;
    ngx_uint_t              nframes, has_pr;
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_header_t       pkt;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;
    static u_char           src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    if (ngx_queue_empty(&ctx->frames)) {
        return 0;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic output sock #%uL %s packet max:%uz min:%uz",
                   qsock->sid.seqnum, ngx_quic_level_name(ctx->level),
                   max, min);

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    hlen = (ctx->level == ssl_encryption_application)
           ? NGX_QUIC_MAX_SHORT_HEADER
           : NGX_QUIC_MAX_LONG_HEADER;

    hlen += EVP_GCM_TLS_TAG_LEN;
    hlen -= NGX_QUIC_MAX_CID_LEN - qsock->cid->len;

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    now = ngx_current_msec;
    nframes = 0;
    p = src;
    len = 0;
    has_pr = 0;

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (!pkt.need_ack && f->need_ack && max > cg->window) {
            max = cg->window;
        }

        if (f->type == NGX_QUIC_FT_PATH_RESPONSE
            || f->type == NGX_QUIC_FT_PATH_CHALLENGE)
        {
            has_pr = 1;
        }

        if (hlen + len >= max) {
            break;
        }

        if (hlen + len + f->len > max) {
            rc = ngx_quic_split_frame(c, f, max - hlen - len);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                break;
            }
        }

        if (f->need_ack) {
            pkt.need_ack = 1;
        }

        ngx_quic_log_frame(c->log, f, 1);

        flen = ngx_quic_create_frame(p, f);
        if (flen == -1) {
            return NGX_ERROR;
        }

        len += flen;
        p += flen;

        f->pnum = ctx->pnum;
        f->first = now;
        f->last = now;
        f->plen = 0;

        nframes++;

        if (f->flush) {
            break;
        }
    }

    if (nframes == 0) {
        return 0;
    }

    out.data = src;
    out.len = len;

    pkt.keys = qc->keys;
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT;

    if (ctx->level == ssl_encryption_initial) {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL;

    } else if (ctx->level == ssl_encryption_handshake) {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_HANDSHAKE;

    } else {
        if (qc->key_phase) {
            pkt.flags |= NGX_QUIC_PKT_KPHASE;
        }
    }

    ngx_quic_set_packet_number(&pkt, ctx);

    pkt.version = qc->version;
    pkt.log = c->log;
    pkt.level = ctx->level;

    pkt.dcid.data = qsock->cid->id;
    pkt.dcid.len = qsock->cid->len;

    pkt.scid.data = qsock->sid.id;
    pkt.scid.len = qsock->sid.len;

    pad_len = 4;

    if (min || has_pr) {
        hlen = EVP_GCM_TLS_TAG_LEN
               + ngx_quic_create_header(&pkt, NULL, out.len, NULL);

        /*
         * An endpoint MUST expand datagrams that contain a
         * PATH_CHALLENGE frame to at least the smallest allowed
         * maximum datagram size of 1200 bytes, unless the
         * anti-amplification limit for the path does not permit
         * sending a datagram of this size.
         *
         * (same applies to PATH_RESPONSE frames)
         */

        if (has_pr) {
            min = ngx_max(1200, min);
        }

        if (min > hlen + pad_len) {
            pad_len = min - hlen;
        }
    }

    if (out.len < pad_len) {
        ngx_memset(p, NGX_QUIC_FT_PADDING, pad_len - out.len);
        out.len = pad_len;
    }

    pkt.payload = out;

    res.data = data;

    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet tx %s bytes:%ui"
                   " need_ack:%d number:%L encoded nl:%d trunc:0x%xD",
                   ngx_quic_level_name(ctx->level), out.len, pkt.need_ack,
                   pkt.number, pkt.num_len, pkt.trunc);

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->pnum++;

    if (pkt.need_ack) {
        /* move frames into the sent queue to wait for ack */

        if (!qc->closing) {
            q = ngx_queue_head(&ctx->frames);
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);
            f->plen = res.len;

            do {
                q = ngx_queue_head(&ctx->frames);
                ngx_queue_remove(q);
                ngx_queue_insert_tail(&ctx->sent, q);
            } while (--nframes);
        }

        cg->in_flight += res.len;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion send if:%uz", cg->in_flight);
    }

    while (nframes--) {
        q = ngx_queue_head(&ctx->frames);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(q);
        ngx_quic_free_frame(c, f);
    }

    return res.len;
}


static ssize_t
ngx_quic_send(ngx_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen)
{
    ngx_buf_t         b;
    socklen_t         orig_socklen;
    ngx_chain_t       cl, *res;
    struct sockaddr  *orig_sockaddr;

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.pos = b.start = buf;
    b.last = b.end = buf + len;
    b.last_buf = 1;
    b.temporary = 1;

    cl.buf = &b;
    cl.next= NULL;

    orig_socklen = c->socklen;
    orig_sockaddr = c->sockaddr;

    c->sockaddr = sockaddr;
    c->socklen = socklen;

    res = c->send_chain(c, &cl, 0);

    c->sockaddr = orig_sockaddr;
    c->socklen = orig_socklen;

    if (res == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    return len;
}


static void
ngx_quic_set_packet_number(ngx_quic_header_t *pkt, ngx_quic_send_ctx_t *ctx)
{
    uint64_t  delta;

    delta = ctx->pnum - ctx->largest_ack;
    pkt->number = ctx->pnum;

    if (delta <= 0x7F) {
        pkt->num_len = 1;
        pkt->trunc = ctx->pnum & 0xff;

    } else if (delta <= 0x7FFF) {
        pkt->num_len = 2;
        pkt->flags |= 0x1;
        pkt->trunc = ctx->pnum & 0xffff;

    } else if (delta <= 0x7FFFFF) {
        pkt->num_len = 3;
        pkt->flags |= 0x2;
        pkt->trunc = ctx->pnum & 0xffffff;

    } else {
        pkt->num_len = 4;
        pkt->flags |= 0x3;
        pkt->trunc = ctx->pnum & 0xffffffff;
    }
}


ngx_int_t
ngx_quic_negotiate_version(ngx_connection_t *c, ngx_quic_header_t *inpkt)
{
    size_t             len;
    ngx_quic_header_t  pkt;
    static u_char      buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sending version negotiation packet");

    pkt.log = c->log;
    pkt.flags = NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_FIXED_BIT;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;

    len = ngx_quic_create_version_negotiation(&pkt, buf);

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic vnego packet to send len:%uz %*xs", len, len, buf);
#endif

    (void) ngx_quic_send(c, buf, len, c->sockaddr, c->socklen);

    return NGX_ERROR;
}


int
ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn, enum ssl_encryption_level_t level,
    uint8_t alert)
{
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_send_alert() lvl:%d  alert:%d",
                   (int) level, (int) alert);

    qc = ngx_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error_level = level;
    qc->error = NGX_QUIC_ERR_CRYPTO(alert);
    qc->error_reason = "TLS alert";
    qc->error_app = 0;
    qc->error_ftype = 0;

    if (ngx_quic_send_cc(c) != NGX_OK) {
        return 0;
    }

    return 1;
}


ngx_int_t
ngx_quic_send_stateless_reset(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *pkt)
{
    u_char    *token;
    size_t     len, max;
    uint16_t   rndbytes;
    u_char     buf[NGX_QUIC_MAX_SR_PACKET];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic handle stateless reset output");

    if (pkt->len <= NGX_QUIC_MIN_PKT_LEN) {
        return NGX_DECLINED;
    }

    if (pkt->len <= NGX_QUIC_MIN_SR_PACKET) {
        len = pkt->len - 1;

    } else {
        max = ngx_min(NGX_QUIC_MAX_SR_PACKET, pkt->len * 3);

        if (RAND_bytes((u_char *) &rndbytes, sizeof(rndbytes)) != 1) {
            return NGX_ERROR;
        }

        len = (rndbytes % (max - NGX_QUIC_MIN_SR_PACKET + 1))
              + NGX_QUIC_MIN_SR_PACKET;
    }

    if (RAND_bytes(buf, len - NGX_QUIC_SR_TOKEN_LEN) != 1) {
        return NGX_ERROR;
    }

    buf[0] &= ~NGX_QUIC_PKT_LONG;
    buf[0] |= NGX_QUIC_PKT_FIXED_BIT;

    token = &buf[len - NGX_QUIC_SR_TOKEN_LEN];

    if (ngx_quic_new_sr_token(c, &pkt->dcid, conf->sr_token_key, token)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    (void) ngx_quic_send(c, buf, len, c->sockaddr, c->socklen);

    return NGX_DECLINED;
}


ngx_int_t
ngx_quic_send_cc(ngx_connection_t *c)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->draining) {
        return NGX_OK;
    }

    if (qc->closing
        && ngx_current_msec - qc->last_cc < NGX_QUIC_CC_MIN_INTERVAL)
    {
        /* dot not send CC too often */
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = qc->error_level;
    frame->type = qc->error_app ? NGX_QUIC_FT_CONNECTION_CLOSE_APP
                                : NGX_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = qc->error;
    frame->u.close.frame_type = qc->error_ftype;

    if (qc->error_reason) {
        frame->u.close.reason.len = ngx_strlen(qc->error_reason);
        frame->u.close.reason.data = (u_char *) qc->error_reason;
    }

    ngx_quic_queue_frame(qc, frame);

    qc->last_cc = ngx_current_msec;

    return ngx_quic_output(c);
}


ngx_int_t
ngx_quic_send_early_cc(ngx_connection_t *c, ngx_quic_header_t *inpkt,
    ngx_uint_t err, const char *reason)
{
    ssize_t            len;
    ngx_str_t          res;
    ngx_quic_frame_t   frame;
    ngx_quic_header_t  pkt;

    static u_char       src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char       dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_memzero(&frame, sizeof(ngx_quic_frame_t));
    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    frame.level = inpkt->level;
    frame.type = NGX_QUIC_FT_CONNECTION_CLOSE;
    frame.u.close.error_code = err;

    frame.u.close.reason.data = (u_char *) reason;
    frame.u.close.reason.len = ngx_strlen(reason);

    len = ngx_quic_create_frame(NULL, &frame);
    if (len > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        return NGX_ERROR;
    }

    ngx_quic_log_frame(c->log, &frame, 1);

    len = ngx_quic_create_frame(src, &frame);
    if (len == -1) {
        return NGX_ERROR;
    }

    pkt.keys = ngx_quic_keys_new(c->pool);
    if (pkt.keys == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_keys_set_initial_secret(c->pool, pkt.keys, &inpkt->dcid,
                                         inpkt->version)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    pkt.flags = NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG
                | NGX_QUIC_PKT_INITIAL;

    pkt.num_len = 1;
    /*
     * pkt.num = 0;
     * pkt.trunc = 0;
     */

    pkt.version = inpkt->version;
    pkt.log = c->log;
    pkt.level = inpkt->level;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;
    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_send(c, res.data, res.len, c->sockaddr, c->socklen)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_send_retry(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *inpkt)
{
    time_t             expires;
    ssize_t            len;
    ngx_str_t          res, token;
    ngx_quic_header_t  pkt;

    u_char             buf[NGX_QUIC_RETRY_BUFFER_SIZE];
    u_char             dcid[NGX_QUIC_SERVER_CID_LEN];

    expires = ngx_time() + NGX_QUIC_RETRY_TOKEN_LIFETIME;

    if (ngx_quic_new_token(c, c->sockaddr, c->socklen, conf->av_token_key,
                           &token, &inpkt->dcid, expires, 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_RETRY;
    pkt.version = inpkt->version;
    pkt.log = c->log;

    pkt.odcid = inpkt->dcid;
    pkt.dcid = inpkt->scid;

    /* TODO: generate routable dcid */
    if (RAND_bytes(dcid, NGX_QUIC_SERVER_CID_LEN) != 1) {
        return NGX_ERROR;
    }

    pkt.scid.len = NGX_QUIC_SERVER_CID_LEN;
    pkt.scid.data = dcid;

    pkt.token = token;

    res.data = buf;

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet to send len:%uz %xV", res.len, &res);
#endif

    len = ngx_quic_send(c, res.data, res.len, c->sockaddr, c->socklen);
    if (len == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic retry packet sent to %xV", &pkt.dcid);

    /*
     * quic-transport 17.2.5.1:  A server MUST NOT send more than one Retry
     * packet in response to a single UDP datagram.
     * NGX_DONE will stop quic_input() from processing further
     */
    return NGX_DONE;
}


ngx_int_t
ngx_quic_send_new_token(ngx_connection_t *c, ngx_quic_path_t *path)
{
    time_t                  expires;
    ngx_str_t               token;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    expires = ngx_time() + NGX_QUIC_NEW_TOKEN_LIFETIME;

    if (ngx_quic_new_token(c, path->sockaddr, path->socklen,
                           qc->conf->av_token_key, &token, NULL, expires, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_NEW_TOKEN;
    frame->u.token.length = token.len;
    frame->u.token.data = token.data;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_quic_send_ack(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    size_t                  len, left;
    uint64_t                ack_delay;
    ngx_buf_t              *b;
    ngx_uint_t              i;
    ngx_chain_t            *cl, **ll;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ack_delay = ngx_current_msec - ctx->largest_received;
    ack_delay *= 1000;
    ack_delay >>= qc->tp.ack_delay_exponent;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    ll = &frame->data;
    b = NULL;

    for (i = 0; i < ctx->nranges; i++) {
        len = ngx_quic_create_ack_range(NULL, ctx->ranges[i].gap,
                                        ctx->ranges[i].range);

        left = b ? b->end - b->last : 0;

        if (left < len) {
            cl = ngx_quic_alloc_buf(c);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            left = b->end - b->last;

            if (left < len) {
                return NGX_ERROR;
            }
        }

        b->last += ngx_quic_create_ack_range(b->last, ctx->ranges[i].gap,
                                             ctx->ranges[i].range);

        frame->u.ack.ranges_length += len;
    }

    *ll = NULL;

    frame->level = ctx->level;
    frame->type = NGX_QUIC_FT_ACK;
    frame->u.ack.largest = ctx->largest_range;
    frame->u.ack.delay = ack_delay;
    frame->u.ack.range_count = ctx->nranges;
    frame->u.ack.first_range = ctx->first_range;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_quic_send_ack_range(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t smallest, uint64_t largest)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ctx->level;
    frame->type = NGX_QUIC_FT_ACK;
    frame->u.ack.largest = largest;
    frame->u.ack.delay = 0;
    frame->u.ack.range_count = 0;
    frame->u.ack.first_range = largest - smallest;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ssize_t
ngx_quic_frame_sendto(ngx_connection_t *c, ngx_quic_frame_t *frame,
    size_t min, struct sockaddr *sockaddr, socklen_t socklen)
{
    ssize_t                 len;
    ngx_str_t               res;
    ngx_quic_header_t       pkt;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    static u_char           src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char           dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = ngx_quic_get_connection(c);

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    len = ngx_quic_create_frame(NULL, frame);
    if (len > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        return -1;
    }

    ngx_quic_log_frame(c->log, frame, 1);

    len = ngx_quic_create_frame(src, frame);
    if (len == -1) {
        return -1;
    }

    if (len < (ssize_t) min) {
        ngx_memset(src + len, NGX_QUIC_FT_PADDING, min - len);
        len = min;
    }

    pkt.keys = qc->keys;
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT;

    if (qc->key_phase) {
        pkt.flags |= NGX_QUIC_PKT_KPHASE;
    }

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);

    ngx_quic_set_packet_number(&pkt, ctx);

    pkt.version = qc->version;
    pkt.log = c->log;
    pkt.level = ctx->level;

    pkt.dcid.data = qc->socket->cid->id;
    pkt.dcid.len = qc->socket->cid->len;

    pkt.scid.data = qc->socket->sid.id;
    pkt.scid.len = qc->socket->sid.len;

    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return -1;
    }

    ctx->pnum++;

    len = ngx_quic_send(c, res.data, res.len, sockaddr, socklen);

    return len;
}
