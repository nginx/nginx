
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


ngx_int_t
ngx_quic_open_sockets(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_str_t *scid, ngx_str_t *dcid)
{
    u_char                *p;
    ngx_str_t              sid;
    ngx_quic_socket_t     *qsock, *tmp;
    ngx_quic_client_id_t  *cid;

    /*
     * qc->path = NULL
     *
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

    qsock = ngx_quic_create_socket(c, qc);
    if (qsock == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_listen(c, qc, qsock) != NGX_OK) {
        return NGX_ERROR;
    }

    qsock->used = 1;

    ngx_memcpy(&qsock->sockaddr, c->sockaddr, c->socklen);
    qsock->socklen = c->socklen;

    c->udp = &qsock->udp;

    sid.data = qsock->sid.id;
    sid.len = qsock->sid.len;

    if (ngx_quic_new_sr_token(c, &sid, qc->conf->sr_token_key, qc->tp.sr_token)
        != NGX_OK)
    {
        goto failed;
    }

    p = ngx_pnalloc(c->pool, qsock->sid.len);
    if (p == NULL) {
        goto failed;
    }

    ngx_memcpy(p, qsock->sid.id, qsock->sid.len);
    qc->tp.initial_scid.data = p;
    qc->tp.initial_scid.len = qsock->sid.len;

    cid = ngx_quic_create_client_id(c, scid, 0, NULL);
    if (cid == NULL) {
        goto failed;
    }

    qc->path = ngx_quic_new_path(c, c->sockaddr, c->socklen, cid);
    if (qc->path == NULL) {
        goto failed;
    }

    qc->path->tag = NGX_QUIC_PATH_ACTIVE;

    ngx_quic_path_dbg(c, "set active", qc->path);

    if (dcid) {
        tmp = ngx_pcalloc(c->pool, sizeof(ngx_quic_socket_t));
        if (tmp == NULL) {
            goto failed;
        }

        tmp->sid.seqnum = NGX_QUIC_UNSET_PN; /* temporary socket */

        ngx_memcpy(tmp->sid.id, dcid->data, dcid->len);
        tmp->sid.len = dcid->len;

        if (ngx_quic_listen(c, qc, tmp) != NGX_OK) {
            goto failed;
        }
    }

    return NGX_OK;

failed:

    if (c->listening) {
        ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node);
    }

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

    if (c->listening) {
        ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node);
    }

    qc->nsockets--;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket seq:%L closed nsock:%ui",
                   (int64_t) qsock->sid.seqnum, qc->nsockets);
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

    qsock->udp.connection = c;
    qsock->udp.node.key = ngx_crc32_long(id.data, id.len);
    qsock->udp.key = id;
    qsock->quic = qc;

    if (c->listening) {
        ngx_rbtree_insert(&c->listening->rbtree, &qsock->udp.node);
    }

    ngx_queue_insert_tail(&qc->sockets, &qsock->queue);

    qc->nsockets++;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket seq:%L listening at sid:%*xs nsock:%ui",
                   (int64_t) qsock->sid.seqnum, qsock->sid.len, qsock->sid.id,
                   qc->nsockets);

    return NGX_OK;
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
