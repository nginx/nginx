
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


ngx_int_t
ngx_quic_open_sockets(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt)
{
    ngx_quic_path_t       *path;
    ngx_quic_socket_t     *qsock, *tmp;
    ngx_quic_client_id_t  *cid;

    /*
     * qc->nclient_ids = 0
     * qc->nsockets = 0
     * qc->max_retired_seqnum = 0
     * qc->client_seqnum = 0
     */

    ngx_queue_init(&qc->sockets);
    ngx_queue_init(&qc->free_sockets);

    ngx_queue_init(&qc->paths);
    ngx_queue_init(&qc->free_paths);

    ngx_queue_init(&qc->client_ids);
    ngx_queue_init(&qc->free_client_ids);

    qc->tp.original_dcid.len = pkt->odcid.len;
    qc->tp.original_dcid.data = ngx_pstrdup(c->pool, &pkt->odcid);
    if (qc->tp.original_dcid.data == NULL) {
         return NGX_ERROR;
    }

    /* socket to use for further processing (id auto-generated) */
    qsock = ngx_quic_create_socket(c, qc);
    if (qsock == NULL) {
        return NGX_ERROR;
    }

    /* socket is listening at new server id */
    if (ngx_quic_listen(c, qc, qsock) != NGX_OK) {
        return NGX_ERROR;
    }

    qc->tp.initial_scid.len = qsock->sid.len;
    qc->tp.initial_scid.data = ngx_pnalloc(c->pool, qsock->sid.len);
    if (qc->tp.initial_scid.data == NULL) {
        goto failed;
    }
    ngx_memcpy(qc->tp.initial_scid.data, qsock->sid.id, qsock->sid.len);

    /* for all packets except first, this is set at udp layer */
    c->udp = &qsock->udp;

    /* ngx_quic_get_connection(c) macro is now usable */

    /* we have a client identified by scid */
    cid = ngx_quic_create_client_id(c, &pkt->scid, 0, NULL);
    if (cid == NULL) {
        goto failed;
    }

    /* the client arrived from this path */
    path = ngx_quic_add_path(c, c->sockaddr, c->socklen);
    if (path == NULL) {
        goto failed;
    }

    if (pkt->validated) {
        path->state = NGX_QUIC_PATH_VALIDATED;
        path->limited = 0;
    }

    /* now bind socket to client and path */
    ngx_quic_connect(c, qsock, path, cid);

    tmp = ngx_pcalloc(c->pool, sizeof(ngx_quic_socket_t));
    if (tmp == NULL) {
        goto failed;
    }

    tmp->sid.seqnum = NGX_QUIC_UNSET_PN; /* temporary socket */

    ngx_memcpy(tmp->sid.id, pkt->odcid.data, pkt->odcid.len);
    tmp->sid.len = pkt->odcid.len;

    if (ngx_quic_listen(c, qc, tmp) != NGX_OK) {
        goto failed;
    }

    ngx_quic_connect(c, tmp, path, cid);

    /* use this socket as default destination */
    qc->socket = qsock;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic active socket is #%uL:%uL:%uL (%s)",
                   qsock->sid.seqnum, qsock->cid->seqnum, qsock->path->seqnum,
                   ngx_quic_path_state_str(qsock->path));

    return NGX_OK;

failed:

    ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node);
    c->udp = NULL;

    return NGX_ERROR;
}


ngx_quic_socket_t *
ngx_quic_create_socket(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_queue_t        *q;
    ngx_quic_socket_t  *sock;

    if (!ngx_queue_empty(&qc->free_sockets)) {

        q = ngx_queue_head(&qc->free_sockets);
        sock = ngx_queue_data(q, ngx_quic_socket_t, queue);

        ngx_queue_remove(&sock->queue);

        ngx_memzero(sock, sizeof(ngx_quic_socket_t));

    } else {

        sock = ngx_pcalloc(c->pool, sizeof(ngx_quic_socket_t));
        if (sock == NULL) {
            return NULL;
        }
    }

    sock->sid.len = NGX_QUIC_SERVER_CID_LEN;
    if (ngx_quic_create_server_id(c, sock->sid.id) != NGX_OK) {
        return NULL;
    }

    sock->sid.seqnum = qc->server_seqnum++;

    return sock;
}


void
ngx_quic_close_socket(ngx_connection_t *c, ngx_quic_socket_t *qsock)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_queue_remove(&qsock->queue);
    ngx_queue_insert_head(&qc->free_sockets, &qsock->queue);

    ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node);
    qc->nsockets--;

    if (qsock->path) {
        ngx_quic_unref_path(c, qsock->path);
    }

    if (qsock->cid) {
        ngx_quic_unref_client_id(c, qsock->cid);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket #%L closed nsock:%ui",
                   (int64_t) qsock->sid.seqnum, qc->nsockets);
}


void
ngx_quic_unref_path(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_quic_connection_t  *qc;

    path->refcnt--;

    if (path->refcnt) {
        return;
    }

    qc = ngx_quic_get_connection(c);

    ngx_queue_remove(&path->queue);
    ngx_queue_insert_head(&qc->free_paths, &path->queue);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path #%uL addr:%V removed",
                   path->seqnum, &path->addr_text);
}


ngx_int_t
ngx_quic_listen(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock)
{
    ngx_str_t              id;
    ngx_quic_server_id_t  *sid;

    sid = &qsock->sid;

    id.data = sid->id;
    id.len = sid->len;

    ngx_insert_udp_connection(c, &qsock->udp, &id);

    ngx_queue_insert_tail(&qc->sockets, &qsock->queue);

    qc->nsockets++;
    qsock->quic = qc;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket #%L listening at sid:%xV nsock:%ui",
                   (int64_t) sid->seqnum, &id, qc->nsockets);

    return NGX_OK;
}


void
ngx_quic_connect(ngx_connection_t *c, ngx_quic_socket_t *sock,
    ngx_quic_path_t *path, ngx_quic_client_id_t *cid)
{
    sock->path = path;
    path->refcnt++;

    sock->cid = cid;
    cid->refcnt++;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket #%L connected to cid #%uL path:%uL",
                   (int64_t) sock->sid.seqnum,
                   sock->cid->seqnum, path->seqnum);
}


void
ngx_quic_close_sockets(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    while (!ngx_queue_empty(&qc->sockets)) {
        q = ngx_queue_head(&qc->sockets);
        qsock = ngx_queue_data(q, ngx_quic_socket_t, queue);

        ngx_quic_close_socket(c, qsock);
    }
}


ngx_quic_socket_t *
ngx_quic_find_socket(ngx_connection_t *c, uint64_t seqnum)
{
    ngx_queue_t            *q;
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->sockets);
         q != ngx_queue_sentinel(&qc->sockets);
         q = ngx_queue_next(q))
    {
        qsock = ngx_queue_data(q, ngx_quic_socket_t, queue);

        if (qsock->sid.seqnum == seqnum) {
            return qsock;
        }
    }

    return NULL;
}


ngx_quic_socket_t *
ngx_quic_get_unconnected_socket(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_socket_t      *sock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->sockets);
         q != ngx_queue_sentinel(&qc->sockets);
         q = ngx_queue_next(q))
    {
        sock = ngx_queue_data(q, ngx_quic_socket_t, queue);

        if (sock->cid == NULL) {
            return sock;
        }
    }

    return NULL;
}
