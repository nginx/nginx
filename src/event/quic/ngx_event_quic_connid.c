
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>

#define NGX_QUIC_MAX_SERVER_IDS   8


#if (NGX_QUIC_BPF)
static ngx_int_t ngx_quic_bpf_attach_id(ngx_connection_t *c, u_char *id);
#endif
static ngx_int_t ngx_quic_retire_client_id(ngx_connection_t *c,
    ngx_quic_client_id_t *cid);
static ngx_quic_client_id_t *ngx_quic_alloc_client_id(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
static ngx_int_t ngx_quic_send_server_id(ngx_connection_t *c,
    ngx_quic_server_id_t *sid);


ngx_int_t
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
    ngx_quic_new_conn_id_frame_t *f)
{
    ngx_str_t               id;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *frame;
    ngx_quic_client_id_t   *cid, *item;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (f->seqnum < qc->max_retired_seqnum) {
        /*
         * RFC 9000, 19.15.  NEW_CONNECTION_ID Frame
         *
         *  An endpoint that receives a NEW_CONNECTION_ID frame with
         *  a sequence number smaller than the Retire Prior To field
         *  of a previously received NEW_CONNECTION_ID frame MUST send
         *  a corresponding RETIRE_CONNECTION_ID frame that retires
         *  the newly received connection ID, unless it has already
         *  done so for that sequence number.
         */

        frame = ngx_quic_alloc_frame(c);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = NGX_QUIC_ENCRYPTION_APPLICATION;
        frame->type = NGX_QUIC_FT_RETIRE_CONNECTION_ID;
        frame->u.retire_cid.sequence_number = f->seqnum;

        ngx_quic_queue_frame(qc, frame);

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
         * Transmission errors, timeouts, and retransmissions might cause the
         * same NEW_CONNECTION_ID frame to be received multiple times.
         */

        if (cid->len != f->len
            || ngx_strncmp(cid->id, f->cid, f->len) != 0
            || ngx_strncmp(cid->sr_token, f->srt, NGX_QUIC_SR_TOKEN_LEN) != 0)
        {
            /*
             * ..if a sequence number is used for different connection IDs,
             * the endpoint MAY treat that receipt as a connection error
             * of type PROTOCOL_VIOLATION.
             */
            qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
            qc->error_reason = "seqnum refers to different connection id/token";
            return NGX_ERROR;
        }

    } else {

        id.data = f->cid;
        id.len = f->len;

        if (ngx_quic_create_client_id(c, &id, f->seqnum, f->srt) == NULL) {
            return NGX_ERROR;
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

        if (ngx_quic_retire_client_id(c, cid) != NGX_OK) {
            return NGX_ERROR;
        }
    }

done:

    if (qc->nclient_ids > qc->tp.active_connection_id_limit) {
        /*
         * RFC 9000, 5.1.1.  Issuing Connection IDs
         *
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
ngx_quic_retire_client_id(ngx_connection_t *c, ngx_quic_client_id_t *cid)
{
    ngx_queue_t            *q;
    ngx_quic_path_t        *path;
    ngx_quic_client_id_t   *new_cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!cid->used) {
        return ngx_quic_free_client_id(c, cid);
    }

    /* we are going to retire client id which is in use */

    q = ngx_queue_head(&qc->paths);

    while (q != ngx_queue_sentinel(&qc->paths)) {

        path = ngx_queue_data(q, ngx_quic_path_t, queue);
        q = ngx_queue_next(q);

        if (path->cid != cid) {
            continue;
        }

        if (path == qc->path) {
            /* this is the active path: update it with new CID */
            new_cid = ngx_quic_next_client_id(c);
            if (new_cid == NULL) {
                return NGX_ERROR;
            }

            qc->path->cid = new_cid;
            new_cid->used = 1;

            return ngx_quic_free_client_id(c, cid);
        }

        return ngx_quic_free_path(c, path);
    }

    return NGX_OK;
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


ngx_quic_client_id_t *
ngx_quic_create_client_id(ngx_connection_t *c, ngx_str_t *id,
    uint64_t seqnum, u_char *token)
{
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    cid = ngx_quic_alloc_client_id(c, qc);
    if (cid == NULL) {
        return NULL;
    }

    cid->seqnum = seqnum;

    cid->len = id->len;
    ngx_memcpy(cid->id, id->data, id->len);

    if (token) {
        ngx_memcpy(cid->sr_token, token, NGX_QUIC_SR_TOKEN_LEN);
    }

    ngx_queue_insert_tail(&qc->client_ids, &cid->queue);
    qc->nclient_ids++;

    if (seqnum > qc->client_seqnum) {
        qc->client_seqnum = seqnum;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic cid seq:%uL received id:%uz:%xV:%*xs",
                    cid->seqnum, id->len, id,
                    (size_t) NGX_QUIC_SR_TOKEN_LEN, cid->sr_token);

    return cid;
}


ngx_quic_client_id_t *
ngx_quic_next_client_id(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (!cid->used) {
            return cid;
        }
    }

    return NULL;
}


ngx_int_t
ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_retire_cid_frame_t *f)
{
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (f->sequence_number >= qc->server_seqnum) {
        /*
         * RFC 9000, 19.16.
         *
         *  Receipt of a RETIRE_CONNECTION_ID frame containing a sequence
         *  number greater than any previously sent to the peer MUST be
         *  treated as a connection error of type PROTOCOL_VIOLATION.
         */
        qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "sequence number of id to retire was never issued";

        return NGX_ERROR;
    }

    qsock = ngx_quic_get_socket(c);

    if (qsock->sid.seqnum == f->sequence_number) {

        /*
         * RFC 9000, 19.16.
         *
         * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST
         * NOT refer to the Destination Connection ID field of the packet in
         * which the frame is contained.  The peer MAY treat this as a
         * connection error of type PROTOCOL_VIOLATION.
         */

        qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "sequence number of id to retire refers DCID";

        return NGX_ERROR;
    }

    qsock = ngx_quic_find_socket(c, f->sequence_number);
    if (qsock == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket seq:%uL is retired", qsock->sid.seqnum);

    ngx_quic_close_socket(c, qsock);

    /* restore socket count up to a limit after deletion */
    if (ngx_quic_create_sockets(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_create_sockets(ngx_connection_t *c)
{
    ngx_uint_t              n;
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    n = ngx_min(NGX_QUIC_MAX_SERVER_IDS, qc->ctp.active_connection_id_limit);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic create sockets has:%ui max:%ui", qc->nsockets, n);

    while (qc->nsockets < n) {

        qsock = ngx_quic_create_socket(c, qc);
        if (qsock == NULL) {
            return NGX_ERROR;
        }

        if (ngx_quic_listen(c, qc, qsock) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_quic_send_server_id(c, &qsock->sid) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_send_server_id(ngx_connection_t *c, ngx_quic_server_id_t *sid)
{
    ngx_str_t               dcid;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    dcid.len = sid->len;
    dcid.data = sid->id;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame->type = NGX_QUIC_FT_NEW_CONNECTION_ID;
    frame->u.ncid.seqnum = sid->seqnum;
    frame->u.ncid.retire = 0;
    frame->u.ncid.len = NGX_QUIC_SERVER_CID_LEN;
    ngx_memcpy(frame->u.ncid.cid, sid->id, NGX_QUIC_SERVER_CID_LEN);

    if (ngx_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key,
                              frame->u.ncid.srt)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_quic_free_client_id(ngx_connection_t *c, ngx_quic_client_id_t *cid)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame->type = NGX_QUIC_FT_RETIRE_CONNECTION_ID;
    frame->u.retire_cid.sequence_number = cid->seqnum;

    ngx_quic_queue_frame(qc, frame);

    /* we are no longer going to use this client id */

    ngx_queue_remove(&cid->queue);
    ngx_queue_insert_head(&qc->free_client_ids, &cid->queue);

    qc->nclient_ids--;

    return NGX_OK;
}
