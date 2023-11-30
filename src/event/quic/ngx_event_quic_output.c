
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_MAX_UDP_SEGMENT_BUF  65487 /* 65K - IPv6 header */
#define NGX_QUIC_MAX_SEGMENTS            64 /* UDP_MAX_SEGMENTS */

#define NGX_QUIC_RETRY_TOKEN_LIFETIME     3 /* seconds */
#define NGX_QUIC_NEW_TOKEN_LIFETIME     600 /* seconds */
#define NGX_QUIC_RETRY_BUFFER_SIZE      256
    /* 1 flags + 4 version + 3 x (1 + 20) s/o/dcid + itag + token(64) */

/*
 * RFC 9000, 10.3.  Stateless Reset
 *
 * Endpoints MUST discard packets that are too small to be valid QUIC
 * packets.  With the set of AEAD functions defined in [QUIC-TLS],
 * short header packets that are smaller than 21 bytes are never valid.
 */
#define NGX_QUIC_MIN_PKT_LEN             21

#define NGX_QUIC_MIN_SR_PACKET           43 /* 5 rand + 16 srt + 22 padding */
#define NGX_QUIC_MAX_SR_PACKET         1200

#define NGX_QUIC_CC_MIN_INTERVAL       1000 /* 1s */

#define NGX_QUIC_SOCKET_RETRY_DELAY      10 /* ms, for NGX_AGAIN on write */


#define ngx_quic_log_packet(log, pkt)                                         \
    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, log, 0,                               \
                   "quic packet tx %s bytes:%ui need_ack:%d"                  \
                   " number:%L encoded nl:%d trunc:0x%xD",                    \
                   ngx_quic_level_name((pkt)->level), (pkt)->payload.len,     \
                   (pkt)->need_ack, (pkt)->number, (pkt)->num_len,            \
                    (pkt)->trunc);


static ngx_int_t ngx_quic_create_datagrams(ngx_connection_t *c);
static void ngx_quic_commit_send(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx);
static void ngx_quic_revert_send(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t pnum);
#if ((NGX_HAVE_UDP_SEGMENT) && (NGX_HAVE_MSGHDR_MSG_CONTROL))
static ngx_uint_t ngx_quic_allow_segmentation(ngx_connection_t *c);
static ngx_int_t ngx_quic_create_segments(ngx_connection_t *c);
static ssize_t ngx_quic_send_segments(ngx_connection_t *c, u_char *buf,
    size_t len, struct sockaddr *sockaddr, socklen_t socklen, size_t segment);
#endif
static ssize_t ngx_quic_output_packet(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, u_char *data, size_t max, size_t min);
static void ngx_quic_init_packet(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    ngx_quic_header_t *pkt, ngx_quic_path_t *path);
static ngx_uint_t ngx_quic_get_padding_level(ngx_connection_t *c);
static ssize_t ngx_quic_send(ngx_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen);
static void ngx_quic_set_packet_number(ngx_quic_header_t *pkt,
    ngx_quic_send_ctx_t *ctx);


ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    size_t                  in_flight;
    ngx_int_t               rc;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    c->log->action = "sending frames";

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    in_flight = cg->in_flight;

#if ((NGX_HAVE_UDP_SEGMENT) && (NGX_HAVE_MSGHDR_MSG_CONTROL))
    if (ngx_quic_allow_segmentation(c)) {
        rc = ngx_quic_create_segments(c);
    } else
#endif
    {
        rc = ngx_quic_create_datagrams(c);
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (in_flight == cg->in_flight || qc->closing) {
        /* no ack-eliciting data was sent or we are done */
        return NGX_OK;
    }

    if (!qc->send_timer_set) {
        qc->send_timer_set = 1;
        ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    ngx_quic_set_lost_timer(c);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_create_datagrams(ngx_connection_t *c)
{
    size_t                  len, min;
    ssize_t                 n;
    u_char                 *p;
    uint64_t                preserved_pnum[NGX_QUIC_SEND_CTX_LAST];
    ngx_uint_t              i, pad;
    ngx_quic_path_t        *path;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;
    static u_char           dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    path = qc->path;

    while (cg->in_flight < cg->window) {

        p = dst;

        len = ngx_quic_path_limit(c, path, path->mtu);

        pad = ngx_quic_get_padding_level(c);

        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

            ctx = &qc->send_ctx[i];

            preserved_pnum[i] = ctx->pnum;

            if (ngx_quic_generate_ack(c, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            min = (i == pad && p - dst < NGX_QUIC_MIN_INITIAL_SIZE)
                  ? NGX_QUIC_MIN_INITIAL_SIZE - (p - dst) : 0;

            if (min > len) {
                /* padding can't be applied - avoid sending the packet */

                while (i-- > 0) {
                    ctx = &qc->send_ctx[i];
                    ngx_quic_revert_send(c, ctx, preserved_pnum[i]);
                }

                return NGX_OK;
            }

            n = ngx_quic_output_packet(c, ctx, p, len, min);
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

        if (n == NGX_AGAIN) {
            for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
                ngx_quic_revert_send(c, &qc->send_ctx[i], preserved_pnum[i]);
            }

            ngx_add_timer(&qc->push, NGX_QUIC_SOCKET_RETRY_DELAY);
            break;
        }

        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
            ngx_quic_commit_send(c, &qc->send_ctx[i]);
        }

        path->sent += len;
    }

    return NGX_OK;
}


static void
ngx_quic_commit_send(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    cg = &qc->congestion;

    while (!ngx_queue_empty(&ctx->sending)) {

        q = ngx_queue_head(&ctx->sending);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(q);

        if (f->pkt_need_ack && !qc->closing) {
            ngx_queue_insert_tail(&ctx->sent, q);

            cg->in_flight += f->plen;

        } else {
            ngx_quic_free_frame(c, f);
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion send if:%uz", cg->in_flight);
}


static void
ngx_quic_revert_send(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t pnum)
{
    ngx_queue_t  *q;

    while (!ngx_queue_empty(&ctx->sending)) {

        q = ngx_queue_last(&ctx->sending);
        ngx_queue_remove(q);
        ngx_queue_insert_head(&ctx->frames, q);
    }

    ctx->pnum = pnum;
}


#if ((NGX_HAVE_UDP_SEGMENT) && (NGX_HAVE_MSGHDR_MSG_CONTROL))

static ngx_uint_t
ngx_quic_allow_segmentation(ngx_connection_t *c)
{
    size_t                  bytes, len;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!qc->conf->gso_enabled) {
        return 0;
    }

    if (!qc->path->validated) {
        /* don't even try to be faster on non-validated paths */
        return 0;
    }

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_initial);
    if (!ngx_queue_empty(&ctx->frames)) {
        return 0;
    }

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_handshake);
    if (!ngx_queue_empty(&ctx->frames)) {
        return 0;
    }

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);

    bytes = 0;
    len = ngx_min(qc->path->mtu, NGX_QUIC_MAX_UDP_SEGMENT_BUF);

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        bytes += f->len;

        if (bytes > len * 3) {
            /* require at least ~3 full packets to batch */
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_quic_create_segments(ngx_connection_t *c)
{
    size_t                  len, segsize;
    ssize_t                 n;
    u_char                 *p, *end;
    uint64_t                preserved_pnum;
    ngx_uint_t              nseg;
    ngx_quic_path_t        *path;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;
    static u_char           dst[NGX_QUIC_MAX_UDP_SEGMENT_BUF];

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    path = qc->path;

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);

    if (ngx_quic_generate_ack(c, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    segsize = ngx_min(path->mtu, NGX_QUIC_MAX_UDP_SEGMENT_BUF);
    p = dst;
    end = dst + sizeof(dst);

    nseg = 0;

    preserved_pnum = ctx->pnum;

    for ( ;; ) {

        len = ngx_min(segsize, (size_t) (end - p));

        if (len && cg->in_flight + (p - dst) < cg->window) {

            n = ngx_quic_output_packet(c, ctx, p, len, len);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (n) {
                p += n;
                nseg++;
            }

        } else {
            n = 0;
        }

        if (p == dst) {
            break;
        }

        if (n == 0 || nseg == NGX_QUIC_MAX_SEGMENTS) {
            n = ngx_quic_send_segments(c, dst, p - dst, path->sockaddr,
                                       path->socklen, segsize);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (n == NGX_AGAIN) {
                ngx_quic_revert_send(c, ctx, preserved_pnum);

                ngx_add_timer(&qc->push, NGX_QUIC_SOCKET_RETRY_DELAY);
                break;
            }

            ngx_quic_commit_send(c, ctx);

            path->sent += n;

            p = dst;
            nseg = 0;
            preserved_pnum = ctx->pnum;
        }
    }

    return NGX_OK;
}


static ssize_t
ngx_quic_send_segments(ngx_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen, size_t segment)
{
    size_t           clen;
    ssize_t          n;
    uint16_t        *valp;
    struct iovec     iov;
    struct msghdr    msg;
    struct cmsghdr  *cmsg;

#if (NGX_HAVE_ADDRINFO_CMSG)
    char             msg_control[CMSG_SPACE(sizeof(uint16_t))
                             + CMSG_SPACE(sizeof(ngx_addrinfo_t))];
#else
    char             msg_control[CMSG_SPACE(sizeof(uint16_t))];
#endif

    ngx_memzero(&msg, sizeof(struct msghdr));
    ngx_memzero(msg_control, sizeof(msg_control));

    iov.iov_len = len;
    iov.iov_base = buf;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;

    msg.msg_control = msg_control;
    msg.msg_controllen = sizeof(msg_control);

    cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));

    clen = CMSG_SPACE(sizeof(uint16_t));

    valp = (void *) CMSG_DATA(cmsg);
    *valp = segment;

#if (NGX_HAVE_ADDRINFO_CMSG)
    if (c->listening && c->listening->wildcard && c->local_sockaddr) {
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        clen += ngx_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    msg.msg_controllen = clen;

    n = ngx_sendmsg(c, &msg, 0);
    if (n < 0) {
        return n;
    }

    c->sent += n;

    return n;
}

#endif



static ngx_uint_t
ngx_quic_get_padding_level(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    /*
     * RFC 9000, 14.1.  Initial Datagram Size
     *
     * Similarly, a server MUST expand the payload of all UDP datagrams
     * carrying ack-eliciting Initial packets to at least the smallest
     * allowed maximum datagram size of 1200 bytes.
     */

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_initial);

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->need_ack) {
            for (i = 0; i + 1 < NGX_QUIC_SEND_CTX_LAST; i++) {
                ctx = &qc->send_ctx[i + 1];

                if (ngx_queue_empty(&ctx->frames)) {
                    break;
                }
            }

            return i;
        }
    }

    return NGX_QUIC_SEND_CTX_LAST;
}


static ssize_t
ngx_quic_output_packet(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    u_char *data, size_t max, size_t min)
{
    size_t                  len, pad, min_payload, max_payload;
    u_char                 *p;
    ssize_t                 flen;
    ngx_str_t               res;
    ngx_int_t               rc;
    ngx_uint_t              nframes;
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_header_t       pkt;
    ngx_quic_connection_t  *qc;
    static u_char           src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    if (ngx_queue_empty(&ctx->frames)) {
        return 0;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic output %s packet max:%uz min:%uz",
                   ngx_quic_level_name(ctx->level), max, min);

    qc = ngx_quic_get_connection(c);

    if (!ngx_quic_keys_available(qc->keys, ctx->level, 1)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "quic %s write keys discarded",
                      ngx_quic_level_name(ctx->level));

        while (!ngx_queue_empty(&ctx->frames)) {
            q = ngx_queue_head(&ctx->frames);
            ngx_queue_remove(q);

            f = ngx_queue_data(q, ngx_quic_frame_t, queue);
            ngx_quic_free_frame(c, f);
        }

        return 0;
    }

    ngx_quic_init_packet(c, ctx, &pkt, qc->path);

    min_payload = ngx_quic_payload_size(&pkt, min);
    max_payload = ngx_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    pad = 4 - pkt.num_len;
    min_payload = ngx_max(min_payload, pad);

    if (min_payload > max_payload) {
        return 0;
    }

    now = ngx_current_msec;
    nframes = 0;
    p = src;
    len = 0;

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (len >= max_payload) {
            break;
        }

        if (len + f->len > max_payload) {
            rc = ngx_quic_split_frame(c, f, max_payload - len);

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

        f->pnum = ctx->pnum;
        f->send_time = now;
        f->plen = 0;

        ngx_quic_log_frame(c->log, f, 1);

        flen = ngx_quic_create_frame(p, f);
        if (flen == -1) {
            return NGX_ERROR;
        }

        len += flen;
        p += flen;

        nframes++;
    }

    if (nframes == 0) {
        return 0;
    }

    if (len < min_payload) {
        ngx_memset(p, NGX_QUIC_FT_PADDING, min_payload - len);
        len = min_payload;
    }

    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = data;

    ngx_quic_log_packet(c->log, &pkt);

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->pnum++;

    if (pkt.need_ack) {
        q = ngx_queue_head(&ctx->frames);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        f->plen = res.len;
    }

    while (nframes--) {
        q = ngx_queue_head(&ctx->frames);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        f->pkt_need_ack = pkt.need_ack;

        ngx_queue_remove(q);
        ngx_queue_insert_tail(&ctx->sending, q);
    }

    return res.len;
}


static void
ngx_quic_init_packet(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    ngx_quic_header_t *pkt, ngx_quic_path_t *path)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_memzero(pkt, sizeof(ngx_quic_header_t));

    pkt->flags = NGX_QUIC_PKT_FIXED_BIT;

    if (ctx->level == ssl_encryption_initial) {
        pkt->flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL;

    } else if (ctx->level == ssl_encryption_handshake) {
        pkt->flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_HANDSHAKE;

    } else {
        if (qc->key_phase) {
            pkt->flags |= NGX_QUIC_PKT_KPHASE;
        }
    }

    pkt->dcid.data = path->cid->id;
    pkt->dcid.len = path->cid->len;

    pkt->scid = qc->tp.initial_scid;

    pkt->version = qc->version;
    pkt->log = c->log;
    pkt->level = ctx->level;

    pkt->keys = qc->keys;

    ngx_quic_set_packet_number(pkt, ctx);
}


static ssize_t
ngx_quic_send(ngx_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen)
{
    ssize_t          n;
    struct iovec     iov;
    struct msghdr    msg;
#if (NGX_HAVE_ADDRINFO_CMSG)
    struct cmsghdr  *cmsg;
    char             msg_control[CMSG_SPACE(sizeof(ngx_addrinfo_t))];
#endif

    ngx_memzero(&msg, sizeof(struct msghdr));

    iov.iov_len = len;
    iov.iov_base = buf;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;

#if (NGX_HAVE_ADDRINFO_CMSG)
    if (c->listening && c->listening->wildcard && c->local_sockaddr) {

        msg.msg_control = msg_control;
        msg.msg_controllen = sizeof(msg_control);
        ngx_memzero(msg_control, sizeof(msg_control));

        cmsg = CMSG_FIRSTHDR(&msg);

        msg.msg_controllen = ngx_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    n = ngx_sendmsg(c, &msg, 0);
    if (n < 0) {
        return n;
    }

    c->sent += n;

    return n;
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

    return NGX_DONE;
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

    frame->ignore_congestion = 1;

    qc->last_cc = ngx_current_msec;

    return ngx_quic_frame_sendto(c, frame, 0, qc->path);
}


ngx_int_t
ngx_quic_send_early_cc(ngx_connection_t *c, ngx_quic_header_t *inpkt,
    ngx_uint_t err, const char *reason)
{
    ssize_t            len;
    ngx_str_t          res;
    ngx_quic_keys_t    keys;
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

    ngx_quic_log_frame(c->log, &frame, 1);

    len = ngx_quic_create_frame(NULL, &frame);
    if (len > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        return NGX_ERROR;
    }

    len = ngx_quic_create_frame(src, &frame);
    if (len == -1) {
        return NGX_ERROR;
    }

    ngx_memzero(&keys, sizeof(ngx_quic_keys_t));

    pkt.keys = &keys;

    if (ngx_quic_keys_set_initial_secret(pkt.keys, &inpkt->dcid, c->log)
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

    ngx_quic_log_packet(c->log, &pkt);

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        ngx_quic_keys_cleanup(pkt.keys);
        return NGX_ERROR;
    }

    if (ngx_quic_send(c, res.data, res.len, c->sockaddr, c->socklen) < 0) {
        ngx_quic_keys_cleanup(pkt.keys);
        return NGX_ERROR;
    }

    ngx_quic_keys_cleanup(pkt.keys);

    return NGX_DONE;
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
    u_char             tbuf[NGX_QUIC_TOKEN_BUF_SIZE];

    expires = ngx_time() + NGX_QUIC_RETRY_TOKEN_LIFETIME;

    token.data = tbuf;
    token.len = NGX_QUIC_TOKEN_BUF_SIZE;

    if (ngx_quic_new_token(c->log, c->sockaddr, c->socklen, conf->av_token_key,
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
    if (len < 0) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic retry packet sent to %xV", &pkt.dcid);

    /*
     * RFC 9000, 17.2.5.1.  Sending a Retry Packet
     *
     * A server MUST NOT send more than one Retry
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
    ngx_chain_t            *out;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    u_char                  tbuf[NGX_QUIC_TOKEN_BUF_SIZE];

    qc = ngx_quic_get_connection(c);

    expires = ngx_time() + NGX_QUIC_NEW_TOKEN_LIFETIME;

    token.data = tbuf;
    token.len = NGX_QUIC_TOKEN_BUF_SIZE;

    if (ngx_quic_new_token(c->log, path->sockaddr, path->socklen,
                           qc->conf->av_token_key, &token, NULL, expires, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    out = ngx_quic_copy_buffer(c, token.data, token.len);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_NEW_TOKEN;
    frame->data = out;
    frame->u.token.length = token.len;

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
            cl = ngx_quic_alloc_chain(c);
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
    frame->len = ngx_quic_create_frame(NULL, frame);

    ngx_queue_insert_head(&ctx->frames, &frame->queue);

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


ngx_int_t
ngx_quic_frame_sendto(ngx_connection_t *c, ngx_quic_frame_t *frame,
    size_t min, ngx_quic_path_t *path)
{
    size_t                  max, max_payload, min_payload, pad;
    ssize_t                 len, sent;
    ngx_str_t               res;
    ngx_msec_t              now;
    ngx_quic_header_t       pkt;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    static u_char           src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char           dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    ctx = ngx_quic_get_send_ctx(qc, frame->level);

    now = ngx_current_msec;

    max = ngx_quic_path_limit(c, path, path->mtu);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic sendto %s packet max:%uz min:%uz",
                   ngx_quic_level_name(ctx->level), max, min);

    if (cg->in_flight >= cg->window && !frame->ignore_congestion) {
        ngx_quic_free_frame(c, frame);
        return NGX_AGAIN;
    }

    ngx_quic_init_packet(c, ctx, &pkt, path);

    min_payload = ngx_quic_payload_size(&pkt, min);
    max_payload = ngx_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    pad = 4 - pkt.num_len;
    min_payload = ngx_max(min_payload, pad);

    if (min_payload > max_payload) {
        ngx_quic_free_frame(c, frame);
        return NGX_AGAIN;
    }

#if (NGX_DEBUG)
    frame->pnum = pkt.number;
#endif

    ngx_quic_log_frame(c->log, frame, 1);

    len = ngx_quic_create_frame(NULL, frame);
    if ((size_t) len > max_payload) {
        ngx_quic_free_frame(c, frame);
        return NGX_AGAIN;
    }

    len = ngx_quic_create_frame(src, frame);
    if (len == -1) {
        ngx_quic_free_frame(c, frame);
        return NGX_ERROR;
    }

    if (len < (ssize_t) min_payload) {
        ngx_memset(src + len, NGX_QUIC_FT_PADDING, min_payload - len);
        len = min_payload;
    }

    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    ngx_quic_log_packet(c->log, &pkt);

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        ngx_quic_free_frame(c, frame);
        return NGX_ERROR;
    }

    frame->pnum = ctx->pnum;
    frame->send_time = now;
    frame->plen = res.len;

    ctx->pnum++;

    sent = ngx_quic_send(c, res.data, res.len, path->sockaddr, path->socklen);
    if (sent < 0) {
        ngx_quic_free_frame(c, frame);
        return sent;
    }

    path->sent += sent;

    if (frame->need_ack && !qc->closing) {
        ngx_queue_insert_tail(&ctx->sent, &frame->queue);

        cg->in_flight += frame->plen;

    } else {
        ngx_quic_free_frame(c, frame);
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion send if:%uz", cg->in_flight);

    if (!qc->send_timer_set) {
        qc->send_timer_set = 1;
        ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    ngx_quic_set_lost_timer(c);

    return NGX_OK;
}


size_t
ngx_quic_path_limit(ngx_connection_t *c, ngx_quic_path_t *path, size_t size)
{
    off_t  max;

    if (!path->validated) {
        max = path->received * 3;
        max = (path->sent >= max) ? 0 : max - path->sent;

        if ((off_t) size > max) {
            return max;
        }
    }

    return size;
}
