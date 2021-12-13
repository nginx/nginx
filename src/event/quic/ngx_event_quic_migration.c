
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


static void ngx_quic_set_connection_path(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_int_t ngx_quic_validate_path(ngx_connection_t *c,
    ngx_quic_socket_t *qsock);
static ngx_int_t ngx_quic_send_path_challenge(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_int_t ngx_quic_path_restore(ngx_connection_t *c);
static ngx_quic_path_t *ngx_quic_alloc_path(ngx_connection_t *c);


ngx_int_t
ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_path_challenge_frame_t *f)
{
    ngx_quic_path_t        *path;
    ngx_quic_frame_t        frame, *fp;
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_memzero(&frame, sizeof(ngx_quic_frame_t));

    frame.level = ssl_encryption_application;
    frame.type = NGX_QUIC_FT_PATH_RESPONSE;
    frame.u.path_response = *f;

    /*
     * RFC 9000, 8.2.2.  Path Validation Responses
     *
     * A PATH_RESPONSE frame MUST be sent on the network path where the
     * PATH_CHALLENGE frame was received.
     */
    qsock = ngx_quic_get_socket(c);
    path = qsock->path;

    /*
     * An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame
     * to at least the smallest allowed maximum datagram size of 1200 bytes.
     */
    if (ngx_quic_frame_sendto(c, &frame, 1200, path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qsock == qc->socket) {
        /*
         * RFC 9000, 9.3.3.  Off-Path Packet Forwarding
         *
         * An endpoint that receives a PATH_CHALLENGE on an active path SHOULD
         * send a non-probing packet in response.
         */

        fp = ngx_quic_alloc_frame(c);
        if (fp == NULL) {
            return NGX_ERROR;
        }

        fp->level = ssl_encryption_application;
        fp->type = NGX_QUIC_FT_PING;

        ngx_quic_queue_frame(qc, fp);
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_path_response_frame(ngx_connection_t *c,
    ngx_quic_path_challenge_frame_t *f)
{
    ngx_queue_t            *q;
    ngx_quic_path_t        *path, *prev;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /*
     * RFC 9000, 8.2.3.  Successful Path Validation
     *
     * A PATH_RESPONSE frame received on any network path validates the path
     * on which the PATH_CHALLENGE was sent.
     */

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (path->state != NGX_QUIC_PATH_VALIDATING) {
            continue;
        }

        if (ngx_memcmp(path->challenge1, f->data, sizeof(f->data)) == 0
            || ngx_memcmp(path->challenge2, f->data, sizeof(f->data)) == 0)
        {
            goto valid;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "quic stale PATH_RESPONSE ignored");

    return NGX_OK;

valid:

    /*
     * RFC 9000, 9.4.  Loss Detection and Congestion Control
     *
     * On confirming a peer's ownership of its new address,
     * an endpoint MUST immediately reset the congestion controller
     * and round-trip time estimator for the new path to initial values
     * unless the only change in the peer's address is its port number.
     */

    prev = qc->backup->path;

    if (ngx_cmp_sockaddr(prev->sockaddr, prev->socklen,
                         path->sockaddr, path->socklen, 0)
        != NGX_OK)
    {
        /* address has changed */
        ngx_memzero(&qc->congestion, sizeof(ngx_quic_congestion_t));

        qc->congestion.window = ngx_min(10 * qc->tp.max_udp_payload_size,
                                   ngx_max(2 * qc->tp.max_udp_payload_size,
                                           14720));
        qc->congestion.ssthresh = (size_t) -1;
        qc->congestion.recovery_start = ngx_current_msec;
    }

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     *  After verifying a new client address, the server SHOULD
     *  send new address validation tokens (Section 8) to the client.
     */

    if (ngx_quic_send_new_token(c, path) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                   "quic path #%uL successfully validated", path->seqnum);

    path->state = NGX_QUIC_PATH_VALIDATED;
    path->limited = 0;

    return NGX_OK;
}


static ngx_quic_path_t *
ngx_quic_alloc_path(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    struct sockaddr        *sa;
    ngx_quic_path_t        *path;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->free_paths)) {

        q = ngx_queue_head(&qc->free_paths);
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        ngx_queue_remove(&path->queue);

        sa = path->sockaddr;
        ngx_memzero(path, sizeof(ngx_quic_path_t));
        path->sockaddr = sa;

    } else {

        path = ngx_pcalloc(c->pool, sizeof(ngx_quic_path_t));
        if (path == NULL) {
            return NULL;
        }

        path->sockaddr = ngx_palloc(c->pool, NGX_SOCKADDRLEN);
        if (path->sockaddr == NULL) {
            return NULL;
        }
    }

    return path;
}


ngx_quic_path_t *
ngx_quic_add_path(ngx_connection_t *c, struct sockaddr *sockaddr,
    socklen_t socklen)
{
    ngx_quic_path_t        *path;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    path = ngx_quic_alloc_path(c);
    if (path == NULL) {
        return NULL;
    }

    path->state = NGX_QUIC_PATH_NEW;
    path->limited = 1;

    path->seqnum = qc->path_seqnum++;
    path->last_seen = ngx_current_msec;

    path->socklen = socklen;
    ngx_memcpy(path->sockaddr, sockaddr, socklen);

    path->addr_text.data = path->text;
    path->addr_text.len = ngx_sock_ntop(sockaddr, socklen, path->text,
                                        NGX_SOCKADDR_STRLEN, 1);

    ngx_queue_insert_tail(&qc->paths, &path->queue);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path #%uL created src:%V",
                   path->seqnum, &path->addr_text);

    return path;
}


ngx_quic_path_t *
ngx_quic_find_path(ngx_connection_t *c, struct sockaddr *sockaddr,
    socklen_t socklen)
{
    ngx_queue_t            *q;
    ngx_quic_path_t        *path;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (ngx_cmp_sockaddr(sockaddr, socklen,
                             path->sockaddr, path->socklen, 1)
            == NGX_OK)
        {
            return path;
        }
    }

    return NULL;
}


ngx_int_t
ngx_quic_update_paths(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    off_t                   len;
    ngx_quic_path_t        *path;
    ngx_quic_socket_t      *qsock;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qsock = ngx_quic_get_socket(c);

    if (c->udp->dgram == NULL) {
        /* 1st ever packet in connection, path already exists */
        path = qsock->path;
        goto update;
    }

    path = ngx_quic_find_path(c, c->udp->dgram->sockaddr,
                              c->udp->dgram->socklen);

    if (path == NULL) {
        path = ngx_quic_add_path(c, c->udp->dgram->sockaddr,
                                 c->udp->dgram->socklen);
        if (path == NULL) {
            return NGX_ERROR;
        }

        if (qsock->path) {
            /* NAT rebinding case: packet to same CID, but from new address */

            ngx_quic_unref_path(c, qsock->path);

            qsock->path = path;
            path->refcnt++;

            goto update;
        }

    } else if (qsock->path) {
        goto update;
    }

    /* prefer unused client IDs if available */
    cid = ngx_quic_next_client_id(c);
    if (cid == NULL) {

        /* try to reuse connection ID used on the same path */
        cid = ngx_quic_used_client_id(c, path);
        if (cid == NULL) {

            qc->error = NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR;
            qc->error_reason = "no available client ids for new path";

            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no available client ids for new path");

            return NGX_ERROR;
        }
    }

    ngx_quic_connect(c, qsock, path, cid);

update:

    if (path->state != NGX_QUIC_PATH_NEW) {
        /* force limits/revalidation for paths that were not seen recently */
        if (ngx_current_msec - path->last_seen > qc->tp.max_idle_timeout) {
            path->state = NGX_QUIC_PATH_NEW;
            path->limited = 1;
            path->sent = 0;
            path->received = 0;
        }
    }

    path->last_seen = ngx_current_msec;

    len = pkt->raw->last - pkt->raw->start;

    /* TODO: this may be too late in some cases;
     *       for example, if error happens during decrypt(), we cannot
     *       send CC, if error happens in 1st packet, due to amplification
     *       limit, because path->received = 0
     *
     *       should we account garbage as received or only decrypting packets?
     */
    path->received += len;

    ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet via #%uL:%uL:%uL"
                   " size:%O path recvd:%O sent:%O limited:%ui",
                   qsock->sid.seqnum, qsock->cid->seqnum, path->seqnum,
                   len, path->received, path->sent, path->limited);

    return NGX_OK;
}


static void
ngx_quic_set_connection_path(ngx_connection_t *c, ngx_quic_path_t *path)
{
    size_t  len;

    ngx_memcpy(c->sockaddr, path->sockaddr,  path->socklen);
    c->socklen = path->socklen;

    if (c->addr_text.data) {
        len = ngx_min(c->addr_text.len, path->addr_text.len);

        ngx_memcpy(c->addr_text.data, path->addr_text.data, len);
        c->addr_text.len = len;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send path set to #%uL addr:%V",
                   path->seqnum, &path->addr_text);
}


ngx_int_t
ngx_quic_handle_migration(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_path_t        *next;
    ngx_quic_socket_t      *qsock;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    /* got non-probing packet via non-active socket with different path */

    qc = ngx_quic_get_connection(c);

    /* current socket, different from active */
    qsock = ngx_quic_get_socket(c);

    next = qsock->path; /* going to migrate to this path... */

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                   "quic migration from #%uL:%uL:%uL (%s)"
                   " to #%uL:%uL:%uL (%s)",
                   qc->socket->sid.seqnum, qc->socket->cid->seqnum,
                   qc->socket->path->seqnum,
                   ngx_quic_path_state_str(qc->socket->path),
                   qsock->sid.seqnum, qsock->cid->seqnum, next->seqnum,
                   ngx_quic_path_state_str(next));

    if (next->state == NGX_QUIC_PATH_NEW) {
        if (ngx_quic_validate_path(c, qsock) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     * An endpoint only changes the address to which it sends packets in
     * response to the highest-numbered non-probing packet.
     */
    if (pkt->pn != ctx->largest_pn) {
        return NGX_OK;
    }

    /* switching connection to new path */

    ngx_quic_set_connection_path(c, next);

    /*
     * RFC 9000, 9.5.  Privacy Implications of Connection Migration
     *
     * An endpoint MUST NOT reuse a connection ID when sending to
     * more than one destination address.
     */

    /* preserve valid path we are migrating from */
    if (qc->socket->path->state == NGX_QUIC_PATH_VALIDATED) {

        if (qc->backup) {
            ngx_quic_close_socket(c, qc->backup);
        }

        qc->backup = qc->socket;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                   "quic backup socket is now #%uL:%uL:%uL (%s)",
                   qc->backup->sid.seqnum, qc->backup->cid->seqnum,
                   qc->backup->path->seqnum,
                   ngx_quic_path_state_str(qc->backup->path));
    }

    qc->socket = qsock;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                   "quic active socket is now #%uL:%uL:%uL (%s)",
                   qsock->sid.seqnum, qsock->cid->seqnum,
                   qsock->path->seqnum, ngx_quic_path_state_str(qsock->path));

    return NGX_OK;
}


static ngx_int_t
ngx_quic_validate_path(ngx_connection_t *c, ngx_quic_socket_t *qsock)
{
    ngx_msec_t              pto;
    ngx_quic_path_t        *path;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    path = qsock->path;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic initiated validation of new path #%uL",
                   path->seqnum);

    path->state = NGX_QUIC_PATH_VALIDATING;

    if (RAND_bytes(path->challenge1, 8) != 1) {
        return NGX_ERROR;
    }

    if (RAND_bytes(path->challenge2, 8) != 1) {
        return NGX_ERROR;
    }

    if (ngx_quic_send_path_challenge(c, path) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);
    pto = ngx_quic_pto(c, ctx);

    path->expires = ngx_current_msec + pto;
    path->tries = NGX_QUIC_PATH_RETRIES;

    if (!qc->path_validation.timer_set) {
        ngx_add_timer(&qc->path_validation, pto);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_send_path_challenge(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_quic_frame_t  frame;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path #%uL send path challenge tries:%ui",
                   path->seqnum, path->tries);

    ngx_memzero(&frame, sizeof(ngx_quic_frame_t));

    frame.level = ssl_encryption_application;
    frame.type = NGX_QUIC_FT_PATH_CHALLENGE;

    ngx_memcpy(frame.u.path_challenge.data, path->challenge1, 8);

    /*
     * RFC 9000, 8.2.1.  Initiating Path Validation
     *
     * An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
     * to at least the smallest allowed maximum datagram size of 1200 bytes,
     * unless the anti-amplification limit for the path does not permit
     * sending a datagram of this size.
     */

     /* same applies to PATH_RESPONSE frames */
    if (ngx_quic_frame_sendto(c, &frame, 1200, path) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memcpy(frame.u.path_challenge.data, path->challenge2, 8);

    if (ngx_quic_frame_sendto(c, &frame, 1200, path) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_quic_path_validation_handler(ngx_event_t *ev)
{
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_msec_int_t          left, next, pto;
    ngx_quic_path_t        *path;
    ngx_connection_t       *c;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    c = ev->data;
    qc = ngx_quic_get_connection(c);

    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);
    pto = ngx_quic_pto(c, ctx);

    next = -1;
    now = ngx_current_msec;

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (path->state != NGX_QUIC_PATH_VALIDATING) {
            continue;
        }

        left = path->expires - now;

        if (left > 0) {

            if (next == -1 || left < next) {
                next = path->expires;
            }

            continue;
        }

        if (--path->tries) {
            path->expires = ngx_current_msec + pto;

            if (next == -1 || pto < next) {
                next = pto;
            }

            /* retransmit */
            (void) ngx_quic_send_path_challenge(c, path);

            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "quic path #%uL validation failed", path->seqnum);

        /* found expired path */

        path->state = NGX_QUIC_PATH_NEW;
        path->limited = 1;

        /*
         * RFC 9000, 9.4.  Loss Detection and Congestion Control
         *
         * If the timer fires before the PATH_RESPONSE is received, the
         * endpoint might send a new PATH_CHALLENGE and restart the timer for
         * a longer period of time.  This timer SHOULD be set as described in
         * Section 6.2.1 of [QUIC-RECOVERY] and MUST NOT be more aggressive.
         */

        if (qc->socket->path != path) {
            /* the path was not actually used */
            continue;
        }

        if (ngx_quic_path_restore(c) != NGX_OK) {
            qc->error = NGX_QUIC_ERR_NO_VIABLE_PATH;
            qc->error_reason = "no viable path";
            ngx_quic_close_connection(c, NGX_ERROR);
            return;
        }
    }

    if (next != -1) {
        ngx_add_timer(&qc->path_validation, next);
    }
}


static ngx_int_t
ngx_quic_path_restore(ngx_connection_t *c)
{
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /*
     * RFC 9000, 9.1.  Probing a New Path
     *
     * Failure to validate a path does not cause the connection to end
     *
     * RFC 9000, 9.3.2.  On-Path Address Spoofing
     *
     * To protect the connection from failing due to such a spurious
     * migration, an endpoint MUST revert to using the last validated
     * peer address when validation of a new peer address fails.
     */

    if (qc->backup == NULL) {
        return NGX_ERROR;
    }

    qc->socket = qc->backup;
    qc->backup = NULL;

    qsock = qc->socket;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                   "quic active socket is restored to #%uL:%uL:%uL"
                   " (%s), no backup",
                   qsock->sid.seqnum, qsock->cid->seqnum, qsock->path->seqnum,
                   ngx_quic_path_state_str(qsock->path));

    ngx_quic_set_connection_path(c, qsock->path);

    return NGX_OK;
}
