
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_MAX_SERVER_IDS   8


static ngx_int_t ngx_quic_create_server_id(ngx_connection_t *c, u_char *id);
#if (NGX_QUIC_BPF)
static ngx_int_t ngx_quic_bpf_attach_id(ngx_connection_t *c, u_char *id);
#endif
static ngx_int_t ngx_quic_retire_connection_id(ngx_connection_t *c,
    enum ssl_encryption_level_t level, uint64_t seqnum);
static ngx_quic_server_id_t *ngx_quic_insert_server_id(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_str_t *id);
static ngx_quic_client_id_t *ngx_quic_alloc_client_id(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
static ngx_quic_server_id_t *ngx_quic_alloc_server_id(ngx_connection_t *c,
    ngx_quic_connection_t *qc);


ngx_int_t
ngx_quic_setup_connection_ids(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt)
{
    ngx_quic_server_id_t   *sid, *osid;
    ngx_quic_client_id_t   *cid;

    /*
     * qc->nclient_ids = 0
     * qc->nserver_ids = 0
     * qc->max_retired_seqnum = 0
     */

    ngx_queue_init(&qc->client_ids);
    ngx_queue_init(&qc->server_ids);
    ngx_queue_init(&qc->free_client_ids);
    ngx_queue_init(&qc->free_server_ids);

    qc->odcid.len = pkt->odcid.len;
    qc->odcid.data = ngx_pstrdup(c->pool, &pkt->odcid);
    if (qc->odcid.data == NULL) {
        return NGX_ERROR;
    }

    qc->tp.original_dcid = qc->odcid;

    qc->scid.len = pkt->scid.len;
    qc->scid.data = ngx_pstrdup(c->pool, &pkt->scid);
    if (qc->scid.data == NULL) {
        return NGX_ERROR;
    }

    qc->dcid.len = NGX_QUIC_SERVER_CID_LEN;
    qc->dcid.data = ngx_pnalloc(c->pool, qc->dcid.len);
    if (qc->dcid.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_create_server_id(c, qc->dcid.data) != NGX_OK) {
        return NGX_ERROR;
    }

    qc->tp.initial_scid = qc->dcid;

    cid = ngx_quic_alloc_client_id(c, qc);
    if (cid == NULL) {
        return NGX_ERROR;
    }

    cid->seqnum = 0;
    cid->len = pkt->scid.len;
    ngx_memcpy(cid->id, pkt->scid.data, pkt->scid.len);

    ngx_queue_insert_tail(&qc->client_ids, &cid->queue);
    qc->nclient_ids++;
    qc->client_seqnum = 0;

    qc->server_seqnum = NGX_QUIC_UNSET_PN;

    osid = ngx_quic_insert_server_id(c, qc, &qc->odcid);
    if (osid == NULL) {
        return NGX_ERROR;
    }

    qc->server_seqnum = 0;

    sid = ngx_quic_insert_server_id(c, qc, &qc->dcid);
    if (sid == NULL) {
        ngx_rbtree_delete(&c->listening->rbtree, &osid->udp.node);
        return NGX_ERROR;
    }

    c->udp = &sid->udp;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_create_server_id(ngx_connection_t *c, u_char *id)
{
    if (RAND_bytes(id, NGX_QUIC_SERVER_CID_LEN) != 1) {
        return NGX_ERROR;
    }

#if (NGX_QUIC_BPF)
    if (ngx_quic_bpf_attach_id(c, id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "quic bpf failed to generate socket key");
        /* ignore error, things still may work */
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic create server id %*xs",
                   (size_t) NGX_QUIC_SERVER_CID_LEN, id);
    return NGX_OK;
}


#if (NGX_QUIC_BPF)

static ngx_int_t
ngx_quic_bpf_attach_id(ngx_connection_t *c, u_char *id)
{
    int        fd;
    uint64_t   cookie;
    socklen_t  optlen;

    fd = c->listening->fd;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "quic getsockopt(SO_COOKIE) failed");

        return NGX_ERROR;
    }

    ngx_quic_dcid_encode_key(id, cookie);

    return NGX_OK;
}

#endif




ngx_int_t
ngx_quic_handle_new_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_new_conn_id_frame_t *f)
{
    ngx_queue_t            *q;
    ngx_quic_client_id_t   *cid, *item;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (f->seqnum < qc->max_retired_seqnum) {
        /*
         *  An endpoint that receives a NEW_CONNECTION_ID frame with
         *  a sequence number smaller than the Retire Prior To field
         *  of a previously received NEW_CONNECTION_ID frame MUST send
         *  a corresponding RETIRE_CONNECTION_ID frame that retires
         *  the newly received connection  ID, unless it has already
         *  done so for that sequence number.
         */

        if (ngx_quic_retire_connection_id(c, pkt->level, f->seqnum) != NGX_OK) {
            return NGX_ERROR;
        }

        goto retire;
    }

    cid = NULL;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (item->seqnum == f->seqnum) {
            cid = item;
            break;
        }
    }

    if (cid) {
        /*
         * Transmission errors, timeouts and retransmissions might cause the
         * same NEW_CONNECTION_ID frame to be received multiple times
         */

        if (cid->len != f->len
            || ngx_strncmp(cid->id, f->cid, f->len) != 0
            || ngx_strncmp(cid->sr_token, f->srt, NGX_QUIC_SR_TOKEN_LEN) != 0)
        {
            /*
             * ..a sequence number is used for different connection IDs,
             * the endpoint MAY treat that receipt as a connection error
             * of type PROTOCOL_VIOLATION.
             */
            qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
            qc->error_reason = "seqnum refers to different connection id/token";
            return NGX_ERROR;
        }

    } else {

        cid = ngx_quic_alloc_client_id(c, qc);
        if (cid == NULL) {
            return NGX_ERROR;
        }

        cid->seqnum = f->seqnum;
        cid->len = f->len;
        ngx_memcpy(cid->id, f->cid, f->len);

        ngx_memcpy(cid->sr_token, f->srt, NGX_QUIC_SR_TOKEN_LEN);

        ngx_queue_insert_tail(&qc->client_ids, &cid->queue);
        qc->nclient_ids++;

        /* always use latest available connection id */
        if (f->seqnum > qc->client_seqnum) {
            qc->scid.len = cid->len;
            qc->scid.data = cid->id;
            qc->client_seqnum = f->seqnum;
        }
    }

retire:

    if (qc->max_retired_seqnum && f->retire <= qc->max_retired_seqnum) {
        /*
         * Once a sender indicates a Retire Prior To value, smaller values sent
         * in subsequent NEW_CONNECTION_ID frames have no effect.  A receiver
         * MUST ignore any Retire Prior To fields that do not increase the
         * largest received Retire Prior To value.
         */
        goto done;
    }

    qc->max_retired_seqnum = f->retire;

    q = ngx_queue_head(&qc->client_ids);

    while (q != ngx_queue_sentinel(&qc->client_ids)) {

        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);
        q = ngx_queue_next(q);

        if (cid->seqnum >= f->retire) {
            continue;
        }

        /* this connection id must be retired */

        if (ngx_quic_retire_connection_id(c, pkt->level, cid->seqnum)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_queue_remove(&cid->queue);
        ngx_queue_insert_head(&qc->free_client_ids, &cid->queue);
        qc->nclient_ids--;
    }

done:

    if (qc->nclient_ids > qc->tp.active_connection_id_limit) {
        /*
         * After processing a NEW_CONNECTION_ID frame and
         * adding and retiring active connection IDs, if the number of active
         * connection IDs exceeds the value advertised in its
         * active_connection_id_limit transport parameter, an endpoint MUST
         * close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
         */
        qc->error = NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR;
        qc->error_reason = "too many connection ids received";
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_retire_connection_id(ngx_connection_t *c,
    enum ssl_encryption_level_t level, uint64_t seqnum)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = level;
    frame->type = NGX_QUIC_FT_RETIRE_CONNECTION_ID;
    frame->u.retire_cid.sequence_number = seqnum;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_retire_cid_frame_t *f)
{
    ngx_queue_t            *q;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->server_ids);
         q != ngx_queue_sentinel(&qc->server_ids);
         q = ngx_queue_next(q))
    {
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        if (sid->seqnum == f->sequence_number) {
            ngx_queue_remove(q);
            ngx_queue_insert_tail(&qc->free_server_ids, &sid->queue);
            ngx_rbtree_delete(&c->listening->rbtree, &sid->udp.node);
            qc->nserver_ids--;
            break;
        }
    }

    return ngx_quic_issue_server_ids(c);
}


ngx_int_t
ngx_quic_issue_server_ids(ngx_connection_t *c)
{
    ngx_str_t               dcid;
    ngx_uint_t              n;
    ngx_quic_frame_t       *frame;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;
    u_char                  id[NGX_QUIC_SERVER_CID_LEN];

    qc = ngx_quic_get_connection(c);

    n = ngx_min(NGX_QUIC_MAX_SERVER_IDS, qc->ctp.active_connection_id_limit);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic issue server ids has:%ui max:%ui", qc->nserver_ids, n);

    while (qc->nserver_ids < n) {
        if (ngx_quic_create_server_id(c, id) != NGX_OK) {
            return NGX_ERROR;
        }

        dcid.len = NGX_QUIC_SERVER_CID_LEN;
        dcid.data = id;

        sid = ngx_quic_insert_server_id(c, qc, &dcid);
        if (sid == NULL) {
            return NGX_ERROR;
        }

        frame = ngx_quic_alloc_frame(c);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_NEW_CONNECTION_ID;
        frame->u.ncid.seqnum = sid->seqnum;
        frame->u.ncid.retire = 0;
        frame->u.ncid.len = NGX_QUIC_SERVER_CID_LEN;
        ngx_memcpy(frame->u.ncid.cid, id, NGX_QUIC_SERVER_CID_LEN);

        if (ngx_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key,
                                  frame->u.ncid.srt)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_quic_queue_frame(qc, frame);
    }

    return NGX_OK;
}


void
ngx_quic_clear_temp_server_ids(ngx_connection_t *c)
{
    ngx_queue_t            *q, *next;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clear temp server ids");

    for (q = ngx_queue_head(&qc->server_ids);
         q != ngx_queue_sentinel(&qc->server_ids);
         q = next)
    {
        next = ngx_queue_next(q);
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        if (sid->seqnum != NGX_QUIC_UNSET_PN) {
            continue;
        }

        ngx_queue_remove(q);
        ngx_queue_insert_tail(&qc->free_server_ids, &sid->queue);
        ngx_rbtree_delete(&c->listening->rbtree, &sid->udp.node);
        qc->nserver_ids--;
    }
}


static ngx_quic_server_id_t *
ngx_quic_insert_server_id(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_str_t *id)
{
    ngx_str_t              dcid;
    ngx_quic_server_id_t  *sid;

    sid = ngx_quic_alloc_server_id(c, qc);
    if (sid == NULL) {
        return NULL;
    }

    sid->quic = qc;

    sid->seqnum = qc->server_seqnum;

    if (qc->server_seqnum != NGX_QUIC_UNSET_PN) {
        qc->server_seqnum++;
    }

    sid->len = id->len;
    ngx_memcpy(sid->id, id->data, id->len);

    ngx_queue_insert_tail(&qc->server_ids, &sid->queue);
    qc->nserver_ids++;

    dcid.data = sid->id;
    dcid.len = sid->len;

    ngx_insert_udp_connection(c, &sid->udp, &dcid);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic insert server id seqnum:%uL id len:%uz %xV",
                   sid->seqnum, id->len, id);

    return sid;
}


static ngx_quic_client_id_t *
ngx_quic_alloc_client_id(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_queue_t           *q;
    ngx_quic_client_id_t  *cid;

    if (!ngx_queue_empty(&qc->free_client_ids)) {

        q = ngx_queue_head(&qc->free_client_ids);
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        ngx_queue_remove(&cid->queue);

        ngx_memzero(cid, sizeof(ngx_quic_client_id_t));

    } else {

        cid = ngx_pcalloc(c->pool, sizeof(ngx_quic_client_id_t));
        if (cid == NULL) {
            return NULL;
        }
    }

    return cid;
}


static ngx_quic_server_id_t *
ngx_quic_alloc_server_id(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_queue_t           *q;
    ngx_quic_server_id_t  *sid;

    if (!ngx_queue_empty(&qc->free_server_ids)) {

        q = ngx_queue_head(&qc->free_server_ids);
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        ngx_queue_remove(&sid->queue);

        ngx_memzero(sid, sizeof(ngx_quic_server_id_t));

    } else {

        sid = ngx_pcalloc(c->pool, sizeof(ngx_quic_server_id_t));
        if (sid == NULL) {
            return NULL;
        }
    }

    return sid;
}
