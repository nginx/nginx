
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_STREAM_GONE     (void *) -1


static ngx_int_t ngx_quic_do_reset_stream(ngx_quic_stream_t *qs,
    ngx_uint_t err);
static ngx_int_t ngx_quic_shutdown_stream_send(ngx_connection_t *c);
static ngx_int_t ngx_quic_shutdown_stream_recv(ngx_connection_t *c);
static ngx_quic_stream_t *ngx_quic_get_stream(ngx_connection_t *c, uint64_t id);
static ngx_int_t ngx_quic_reject_stream(ngx_connection_t *c, uint64_t id);
static void ngx_quic_init_stream_handler(ngx_event_t *ev);
static void ngx_quic_init_streams_handler(ngx_connection_t *c);
static ngx_int_t ngx_quic_do_init_streams(ngx_connection_t *c);
static ngx_quic_stream_t *ngx_quic_create_stream(ngx_connection_t *c,
    uint64_t id);
static void ngx_quic_empty_handler(ngx_event_t *ev);
static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_int_t ngx_quic_stream_flush(ngx_quic_stream_t *qs);
static void ngx_quic_stream_cleanup_handler(void *data);
static ngx_int_t ngx_quic_close_stream(ngx_quic_stream_t *qs);
static ngx_int_t ngx_quic_can_shutdown(ngx_connection_t *c);
static ngx_int_t ngx_quic_control_flow(ngx_quic_stream_t *qs, uint64_t last);
static ngx_int_t ngx_quic_update_flow(ngx_quic_stream_t *qs, uint64_t last);
static ngx_int_t ngx_quic_update_max_stream_data(ngx_quic_stream_t *qs);
static ngx_int_t ngx_quic_update_max_data(ngx_connection_t *c);
static void ngx_quic_set_event(ngx_event_t *ev);


ngx_connection_t *
ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi)
{
    uint64_t                id;
    ngx_connection_t       *pc, *sc;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    pc = c->quic ? c->quic->parent : c;
    qc = ngx_quic_get_connection(pc);

    if (qc->closing) {
        return NULL;
    }

    if (bidi) {
        if (qc->streams.server_streams_bidi
            >= qc->streams.server_max_streams_bidi)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server bidi streams:%uL",
                           qc->streams.server_streams_bidi);
            return NULL;
        }

        id = (qc->streams.server_streams_bidi << 2)
             | NGX_QUIC_STREAM_SERVER_INITIATED;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server bidi stream"
                       " streams:%uL max:%uL id:0x%xL",
                       qc->streams.server_streams_bidi,
                       qc->streams.server_max_streams_bidi, id);

        qc->streams.server_streams_bidi++;

    } else {
        if (qc->streams.server_streams_uni
            >= qc->streams.server_max_streams_uni)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server uni streams:%uL",
                           qc->streams.server_streams_uni);
            return NULL;
        }

        id = (qc->streams.server_streams_uni << 2)
             | NGX_QUIC_STREAM_SERVER_INITIATED
             | NGX_QUIC_STREAM_UNIDIRECTIONAL;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server uni stream"
                       " streams:%uL max:%uL id:0x%xL",
                       qc->streams.server_streams_uni,
                       qc->streams.server_max_streams_uni, id);

        qc->streams.server_streams_uni++;
    }

    qs = ngx_quic_create_stream(pc, id);
    if (qs == NULL) {
        return NULL;
    }

    sc = qs->connection;

    sc->write->active = 1;
    sc->write->ready = 1;

    if (bidi) {
        sc->read->active = 1;
    }

    return sc;
}


void
ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_quic_stream_t   *qn, *qnt;

    for ( ;; ) {
        qn = (ngx_quic_stream_t *) node;
        qnt = (ngx_quic_stream_t *) temp;

        p = (qn->id < qnt->id) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_quic_stream_t *
ngx_quic_find_stream(ngx_rbtree_t *rbtree, uint64_t id)
{
    ngx_rbtree_node_t  *node, *sentinel;
    ngx_quic_stream_t  *qn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        qn = (ngx_quic_stream_t *) node;

        if (id == qn->id) {
            return qn;
        }

        node = (id < qn->id) ? node->left : node->right;
    }

    return NULL;
}


ngx_int_t
ngx_quic_close_streams(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_pool_t         *pool;
    ngx_queue_t        *q, posted_events;
    ngx_rbtree_t       *tree;
    ngx_connection_t   *sc;
    ngx_rbtree_node_t  *node;
    ngx_quic_stream_t  *qs;

    while (!ngx_queue_empty(&qc->streams.uninitialized)) {
        q = ngx_queue_head(&qc->streams.uninitialized);
        ngx_queue_remove(q);

        qs = ngx_queue_data(q, ngx_quic_stream_t, queue);
        pool = qs->connection->pool;

        ngx_close_connection(qs->connection);
        ngx_destroy_pool(pool);
    }

    tree = &qc->streams.tree;

    if (tree->root == tree->sentinel) {
        return NGX_OK;
    }

    ngx_queue_init(&posted_events);

    node = ngx_rbtree_min(tree->root, tree->sentinel);

    while (node) {
        qs = (ngx_quic_stream_t *) node;
        node = ngx_rbtree_next(tree, node);
        sc = qs->connection;

        qs->recv_state = NGX_QUIC_STREAM_RECV_RESET_RECVD;
        qs->send_state = NGX_QUIC_STREAM_SEND_RESET_SENT;

        if (sc == NULL) {
            ngx_quic_close_stream(qs);
            continue;
        }

        sc->read->error = 1;
        sc->read->ready = 1;
        sc->write->error = 1;
        sc->write->ready = 1;

        sc->close = 1;

        if (sc->read->posted) {
            ngx_delete_posted_event(sc->read);
        }

        ngx_post_event(sc->read, &posted_events);
    }

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &posted_events);

    if (tree->root == tree->sentinel) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection has active streams");

    return NGX_AGAIN;
}


ngx_int_t
ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err)
{
    return ngx_quic_do_reset_stream(c->quic, err);
}


static ngx_int_t
ngx_quic_do_reset_stream(ngx_quic_stream_t *qs, ngx_uint_t err)
{
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    if (qs->send_state == NGX_QUIC_STREAM_SEND_DATA_RECVD
        || qs->send_state == NGX_QUIC_STREAM_SEND_RESET_SENT
        || qs->send_state == NGX_QUIC_STREAM_SEND_RESET_RECVD)
    {
        return NGX_OK;
    }

    qs->send_state = NGX_QUIC_STREAM_SEND_RESET_SENT;
    qs->send_final_size = qs->send_offset;

    if (qs->connection) {
        qs->connection->write->error = 1;
    }

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL reset", qs->id);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = qs->id;
    frame->u.reset_stream.error_code = err;
    frame->u.reset_stream.final_size = qs->send_offset;

    ngx_quic_queue_frame(qc, frame);

    ngx_quic_free_buffer(pc, &qs->send);

    return NGX_OK;
}


ngx_int_t
ngx_quic_shutdown_stream(ngx_connection_t *c, int how)
{
    if (how == NGX_RDWR_SHUTDOWN || how == NGX_WRITE_SHUTDOWN) {
        if (ngx_quic_shutdown_stream_send(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (how == NGX_RDWR_SHUTDOWN || how == NGX_READ_SHUTDOWN) {
        if (ngx_quic_shutdown_stream_recv(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_shutdown_stream_send(ngx_connection_t *c)
{
    ngx_quic_stream_t  *qs;

    qs = c->quic;

    if (qs->send_state != NGX_QUIC_STREAM_SEND_READY
        && qs->send_state != NGX_QUIC_STREAM_SEND_SEND)
    {
        return NGX_OK;
    }

    qs->send_state = NGX_QUIC_STREAM_SEND_SEND;
    qs->send_final_size = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, qs->parent->log, 0,
                   "quic stream id:0x%xL send shutdown", qs->id);

    return ngx_quic_stream_flush(qs);
}


static ngx_int_t
ngx_quic_shutdown_stream_recv(ngx_connection_t *c)
{
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;

    if (qs->recv_state != NGX_QUIC_STREAM_RECV_RECV
        && qs->recv_state != NGX_QUIC_STREAM_RECV_SIZE_KNOWN)
    {
        return NGX_OK;
    }

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (qc->conf->stream_close_code == 0) {
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL recv shutdown", qs->id);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = qs->id;
    frame->u.stop_sending.error_code = qc->conf->stream_close_code;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_quic_stream_t *
ngx_quic_get_stream(ngx_connection_t *c, uint64_t id)
{
    uint64_t                min_id;
    ngx_event_t            *rev;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    qs = ngx_quic_find_stream(&qc->streams.tree, id);

    if (qs) {
        return qs;
    }

    if (qc->shutdown || qc->closing) {
        return NGX_QUIC_STREAM_GONE;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL is missing", id);

    if (id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {

        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_uni) {
                return NGX_QUIC_STREAM_GONE;
            }

            qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_uni) {
            return NGX_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_uni) {
            qc->error = NGX_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_uni << 2)
                 | NGX_QUIC_STREAM_UNIDIRECTIONAL;
        qc->streams.client_streams_uni = (id >> 2) + 1;

    } else {

        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_bidi) {
                return NGX_QUIC_STREAM_GONE;
            }

            qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_bidi) {
            return NGX_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_bidi) {
            qc->error = NGX_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_bidi << 2);
        qc->streams.client_streams_bidi = (id >> 2) + 1;
    }

    /*
     * RFC 9000, 2.1.  Stream Types and Identifiers
     *
     * successive streams of each type are created with numerically increasing
     * stream IDs.  A stream ID that is used out of order results in all
     * streams of that type with lower-numbered stream IDs also being opened.
     */

#if (NGX_SUPPRESS_WARN)
    qs = NULL;
#endif

    for ( /* void */ ; min_id <= id; min_id += 0x04) {

        qs = ngx_quic_create_stream(c, min_id);

        if (qs == NULL) {
            if (ngx_quic_reject_stream(c, min_id) != NGX_OK) {
                return NULL;
            }

            continue;
        }

        ngx_queue_insert_tail(&qc->streams.uninitialized, &qs->queue);

        rev = qs->connection->read;
        rev->handler = ngx_quic_init_stream_handler;

        if (qc->streams.initialized) {
            ngx_post_event(rev, &ngx_posted_events);

            if (qc->push.posted) {
                /*
                 * The posted stream can produce output immediately.
                 * By postponing the push event, we coalesce the stream
                 * output with queued frames in one UDP datagram.
                 */

                ngx_delete_posted_event(&qc->push);
                ngx_post_event(&qc->push, &ngx_posted_events);
            }
        }
    }

    if (qs == NULL) {
        return NGX_QUIC_STREAM_GONE;
    }

    return qs;
}


static ngx_int_t
ngx_quic_reject_stream(ngx_connection_t *c, uint64_t id)
{
    uint64_t                code;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    code = (id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
           ? qc->conf->stream_reject_code_uni
           : qc->conf->stream_reject_code_bidi;

    if (code == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL reject err:0x%xL", id, code);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = id;
    frame->u.reset_stream.error_code = code;
    frame->u.reset_stream.final_size = 0;

    ngx_quic_queue_frame(qc, frame);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = id;
    frame->u.stop_sending.error_code = code;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static void
ngx_quic_init_stream_handler(ngx_event_t *ev)
{
    ngx_connection_t   *c;
    ngx_quic_stream_t  *qs;

    c = ev->data;
    qs = c->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic init stream");

    if ((qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0) {
        c->write->active = 1;
        c->write->ready = 1;
    }

    c->read->active = 1;

    ngx_queue_remove(&qs->queue);

    c->listening->handler(c);
}


ngx_int_t
ngx_quic_init_streams(ngx_connection_t *c)
{
    ngx_int_t               rc;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->streams.initialized) {
        return NGX_OK;
    }

    rc = ngx_ssl_ocsp_validate(c);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        c->ssl->handler = ngx_quic_init_streams_handler;
        return NGX_OK;
    }

    return ngx_quic_do_init_streams(c);
}


static void
ngx_quic_init_streams_handler(ngx_connection_t *c)
{
    if (ngx_quic_do_init_streams(c) != NGX_OK) {
        ngx_quic_close_connection(c, NGX_ERROR);
    }
}


static ngx_int_t
ngx_quic_do_init_streams(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic init streams");

    qc = ngx_quic_get_connection(c);

    if (qc->conf->init) {
        if (qc->conf->init(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    for (q = ngx_queue_head(&qc->streams.uninitialized);
         q != ngx_queue_sentinel(&qc->streams.uninitialized);
         q = ngx_queue_next(q))
    {
        qs = ngx_queue_data(q, ngx_quic_stream_t, queue);
        ngx_post_event(qs->connection->read, &ngx_posted_events);
    }

    qc->streams.initialized = 1;

    if (!qc->closing && qc->close.timer_set) {
        ngx_del_timer(&qc->close);
    }

    return NGX_OK;
}


static ngx_quic_stream_t *
ngx_quic_create_stream(ngx_connection_t *c, uint64_t id)
{
    ngx_str_t               addr_text;
    ngx_log_t              *log;
    ngx_pool_t             *pool;
    ngx_uint_t              reusable;
    ngx_queue_t            *q;
    struct sockaddr        *sockaddr;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *qs;
    ngx_pool_cleanup_t     *cln;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL create", id);

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->streams.free)) {
        q = ngx_queue_head(&qc->streams.free);
        qs = ngx_queue_data(q, ngx_quic_stream_t, queue);
        ngx_queue_remove(&qs->queue);

    } else {
        /*
         * the number of streams is limited by transport
         * parameters and application requirements
         */

        qs = ngx_palloc(c->pool, sizeof(ngx_quic_stream_t));
        if (qs == NULL) {
            return NULL;
        }
    }

    ngx_memzero(qs, sizeof(ngx_quic_stream_t));

    qs->node.key = id;
    qs->parent = c;
    qs->id = id;
    qs->send_final_size = (uint64_t) -1;
    qs->recv_final_size = (uint64_t) -1;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        ngx_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        ngx_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sockaddr = ngx_palloc(pool, c->socklen);
    if (sockaddr == NULL) {
        ngx_destroy_pool(pool);
        ngx_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    ngx_memcpy(sockaddr, c->sockaddr, c->socklen);

    if (c->addr_text.data) {
        addr_text.data = ngx_pnalloc(pool, c->addr_text.len);
        if (addr_text.data == NULL) {
            ngx_destroy_pool(pool);
            ngx_queue_insert_tail(&qc->streams.free, &qs->queue);
            return NULL;
        }

        ngx_memcpy(addr_text.data, c->addr_text.data, c->addr_text.len);
        addr_text.len = c->addr_text.len;

    } else {
        addr_text.len = 0;
        addr_text.data = NULL;
    }

    reusable = c->reusable;
    ngx_reusable_connection(c, 0);

    sc = ngx_get_connection(c->fd, log);
    if (sc == NULL) {
        ngx_destroy_pool(pool);
        ngx_queue_insert_tail(&qc->streams.free, &qs->queue);
        ngx_reusable_connection(c, reusable);
        return NULL;
    }

    qs->connection = sc;

    sc->quic = qs;
    sc->shared = 1;
    sc->type = SOCK_STREAM;
    sc->pool = pool;
    sc->ssl = c->ssl;
    sc->sockaddr = sockaddr;
    sc->socklen = c->socklen;
    sc->listening = c->listening;
    sc->addr_text = addr_text;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;
    sc->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    sc->start_time = c->start_time;
    sc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    sc->recv = ngx_quic_stream_recv;
    sc->send = ngx_quic_stream_send;
    sc->send_chain = ngx_quic_stream_send_chain;

    sc->read->log = log;
    sc->write->log = log;

    sc->read->handler = ngx_quic_empty_handler;
    sc->write->handler = ngx_quic_empty_handler;

    log->connection = sc->number;

    if (id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_uni;
            qs->recv_state = NGX_QUIC_STREAM_RECV_DATA_READ;
            qs->send_state = NGX_QUIC_STREAM_SEND_READY;

        } else {
            qs->recv_max_data = qc->tp.initial_max_stream_data_uni;
            qs->recv_state = NGX_QUIC_STREAM_RECV_RECV;
            qs->send_state = NGX_QUIC_STREAM_SEND_DATA_RECVD;
        }

    } else {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_remote;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_local;

        } else {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_local;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_remote;
        }

        qs->recv_state = NGX_QUIC_STREAM_RECV_RECV;
        qs->send_state = NGX_QUIC_STREAM_SEND_READY;
    }

    qs->recv_window = qs->recv_max_data;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        ngx_close_connection(sc);
        ngx_destroy_pool(pool);
        ngx_queue_insert_tail(&qc->streams.free, &qs->queue);
        ngx_reusable_connection(c, reusable);
        return NULL;
    }

    cln->handler = ngx_quic_stream_cleanup_handler;
    cln->data = sc;

    ngx_rbtree_insert(&qc->streams.tree, &qs->node);

    return qs;
}


void
ngx_quic_cancelable_stream(ngx_connection_t *c)
{
    ngx_connection_t       *pc;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (!qs->cancelable) {
        qs->cancelable = 1;

        if (ngx_quic_can_shutdown(pc) == NGX_OK) {
            ngx_reusable_connection(pc, 1);

            if (qc->shutdown) {
                ngx_quic_shutdown_quic(pc);
            }
        }
    }
}


static void
ngx_quic_empty_handler(ngx_event_t *ev)
{
}


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t             len;
    ngx_buf_t          *b;
    ngx_chain_t        *cl, *in;
    ngx_event_t        *rev;
    ngx_connection_t   *pc;
    ngx_quic_stream_t  *qs;

    qs = c->quic;
    pc = qs->parent;
    rev = c->read;

    if (qs->recv_state == NGX_QUIC_STREAM_RECV_RESET_RECVD
        || qs->recv_state == NGX_QUIC_STREAM_RECV_RESET_READ)
    {
        qs->recv_state = NGX_QUIC_STREAM_RECV_RESET_READ;
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL recv buf:%uz", qs->id, size);

    if (size == 0) {
        return 0;
    }

    in = ngx_quic_read_buffer(pc, &qs->recv, size);
    if (in == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    len = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        len += b->last - b->pos;
        buf = ngx_cpymem(buf, b->pos, b->last - b->pos);
    }

    ngx_quic_free_chain(pc, in);

    if (len == 0) {
        rev->ready = 0;

        if (qs->recv_state == NGX_QUIC_STREAM_RECV_DATA_RECVD
            && qs->recv_offset == qs->recv_final_size)
        {
            qs->recv_state = NGX_QUIC_STREAM_RECV_DATA_READ;
        }

        if (qs->recv_state == NGX_QUIC_STREAM_RECV_DATA_READ) {
            rev->eof = 1;
            return 0;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv() not ready", qs->id);
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv len:%z", qs->id, len);

    if (ngx_quic_update_flow(qs, qs->recv_offset + len) != NGX_OK) {
        return NGX_ERROR;
    }

    return len;
}


static ssize_t
ngx_quic_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_buf_t    b;
    ngx_chain_t  cl;

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.memory = 1;
    b.pos = buf;
    b.last = buf + size;

    cl.buf = &b;
    cl.next = NULL;

    if (ngx_quic_stream_send_chain(c, &cl, 0) == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (b.pos == buf) {
        return NGX_AGAIN;
    }

    return b.pos - buf;
}


static ngx_chain_t *
ngx_quic_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    uint64_t                n, flow;
    ngx_event_t            *wev;
    ngx_connection_t       *pc;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);
    wev = c->write;

    if (qs->send_state != NGX_QUIC_STREAM_SEND_READY
        && qs->send_state != NGX_QUIC_STREAM_SEND_SEND)
    {
        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

    qs->send_state = NGX_QUIC_STREAM_SEND_SEND;

    flow = qs->acked + qc->conf->stream_buffer_size - qs->sent;

    if (flow == 0) {
        wev->ready = 0;
        return in;
    }

    if (limit == 0 || limit > (off_t) flow) {
        limit = flow;
    }

    n = qs->send.size;

    in = ngx_quic_write_buffer(pc, &qs->send, in, limit, qs->sent);
    if (in == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    n = qs->send.size - n;
    c->sent += n;
    qs->sent += n;
    qc->streams.sent += n;

    if (flow == n) {
        wev->ready = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send_chain sent:%uL", n);

    if (ngx_quic_stream_flush(qs) != NGX_OK) {
        return NGX_CHAIN_ERROR;
    }

    return in;
}


static ngx_int_t
ngx_quic_stream_flush(ngx_quic_stream_t *qs)
{
    off_t                   limit, len;
    ngx_uint_t              last;
    ngx_chain_t            *out;
    ngx_quic_frame_t       *frame;
    ngx_connection_t       *pc;
    ngx_quic_connection_t  *qc;

    if (qs->send_state != NGX_QUIC_STREAM_SEND_SEND) {
        return NGX_OK;
    }

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (qc->streams.send_max_data == 0) {
        qc->streams.send_max_data = qc->ctp.initial_max_data;
    }

    limit = ngx_min(qc->streams.send_max_data - qc->streams.send_offset,
                    qs->send_max_data - qs->send_offset);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flush limit:%O", qs->id, limit);

    len = qs->send.offset;

    out = ngx_quic_read_buffer(pc, &qs->send, limit);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    len = qs->send.offset - len;
    last = 0;

    if (qs->send_final_size != (uint64_t) -1
        && qs->send_final_size == qs->send.offset)
    {
        qs->send_state = NGX_QUIC_STREAM_SEND_DATA_SENT;
        last = 1;
    }

    if (len == 0 && !last) {
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM;
    frame->data = out;

    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = last;

    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = qs->send_offset;
    frame->u.stream.length = len;

    ngx_quic_queue_frame(qc, frame);

    qs->send_offset += len;
    qc->streams.send_offset += len;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flush len:%O last:%ui",
                   qs->id, len, last);

    if (qs->connection == NULL) {
        return ngx_quic_close_stream(qs);
    }

    return NGX_OK;
}


static void
ngx_quic_stream_cleanup_handler(void *data)
{
    ngx_connection_t *c = data;

    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, qs->parent->log, 0,
                   "quic stream id:0x%xL cleanup", qs->id);

    if (ngx_quic_shutdown_stream(c, NGX_RDWR_SHUTDOWN) != NGX_OK) {
        qs->connection = NULL;
        goto failed;
    }

    qs->connection = NULL;

    if (ngx_quic_close_stream(qs) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    qc = ngx_quic_get_connection(qs->parent);
    qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;

    ngx_post_event(&qc->close, &ngx_posted_events);
}


static ngx_int_t
ngx_quic_close_stream(ngx_quic_stream_t *qs)
{
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (!qc->closing) {
        /* make sure everything is sent and final size is received */

        if (qs->recv_state == NGX_QUIC_STREAM_RECV_RECV) {
            return NGX_OK;
        }

        if (qs->send_state != NGX_QUIC_STREAM_SEND_DATA_RECVD
            && qs->send_state != NGX_QUIC_STREAM_SEND_RESET_RECVD)
        {
            return NGX_OK;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL close", qs->id);

    ngx_quic_free_buffer(pc, &qs->send);
    ngx_quic_free_buffer(pc, &qs->recv);

    ngx_rbtree_delete(&qc->streams.tree, &qs->node);
    ngx_queue_insert_tail(&qc->streams.free, &qs->queue);

    if (qc->closing) {
        /* schedule handler call to continue ngx_quic_close_connection() */
        ngx_post_event(&qc->close, &ngx_posted_events);
        return NGX_OK;
    }

    if (!pc->reusable && ngx_quic_can_shutdown(pc) == NGX_OK) {
        ngx_reusable_connection(pc, 1);
    }

    if (qc->shutdown) {
        ngx_quic_shutdown_quic(pc);
        return NGX_OK;
    }

    if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0) {
        frame = ngx_quic_alloc_frame(pc);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_STREAMS;

        if (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_uni;
            frame->u.max_streams.bidi = 0;

        } else {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_bidi;
            frame->u.max_streams.bidi = 1;
        }

        ngx_quic_queue_frame(qc, frame);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_can_shutdown(ngx_connection_t *c)
{
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    tree = &qc->streams.tree;

    if (tree->root != tree->sentinel) {
        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            qs = (ngx_quic_stream_t *) node;

            if (!qs->cancelable) {
                return NGX_DECLINED;
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_stream_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    uint64_t                  last;
    ngx_quic_stream_t        *qs;
    ngx_quic_connection_t    *qc;
    ngx_quic_stream_frame_t  *f;

    qc = ngx_quic_get_connection(c);
    f = &frame->u.stream;

    if ((f->stream_id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->stream_id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    qs = ngx_quic_get_stream(c, f->stream_id);

    if (qs == NULL) {
        return NGX_ERROR;
    }

    if (qs == NGX_QUIC_STREAM_GONE) {
        return NGX_OK;
    }

    if (qs->recv_state != NGX_QUIC_STREAM_RECV_RECV
        && qs->recv_state != NGX_QUIC_STREAM_RECV_SIZE_KNOWN)
    {
        return NGX_OK;
    }

    if (ngx_quic_control_flow(qs, last) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qs->recv_final_size != (uint64_t) -1 && last > qs->recv_final_size) {
        qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
        return NGX_ERROR;
    }

    if (last < qs->recv_offset) {
        return NGX_OK;
    }

    if (f->fin) {
        if (qs->recv_final_size != (uint64_t) -1 && qs->recv_final_size != last)
        {
            qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
            return NGX_ERROR;
        }

        if (qs->recv_last > last) {
            qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
            return NGX_ERROR;
        }

        qs->recv_final_size = last;
        qs->recv_state = NGX_QUIC_STREAM_RECV_SIZE_KNOWN;
    }

    if (ngx_quic_write_buffer(c, &qs->recv, frame->data, f->length, f->offset)
        == NGX_CHAIN_ERROR)
    {
        return NGX_ERROR;
    }

    if (qs->recv_state == NGX_QUIC_STREAM_RECV_SIZE_KNOWN
        && qs->recv.size == qs->recv_final_size)
    {
        qs->recv_state = NGX_QUIC_STREAM_RECV_DATA_RECVD;
    }

    if (qs->connection == NULL) {
        return ngx_quic_close_stream(qs);
    }

    if (f->offset <= qs->recv_offset) {
        ngx_quic_set_event(qs->connection->read);
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_max_data_frame(ngx_connection_t *c,
    ngx_quic_max_data_frame_t *f)
{
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    tree = &qc->streams.tree;

    if (f->max_data <= qc->streams.send_max_data) {
        return NGX_OK;
    }

    if (tree->root == tree->sentinel
        || qc->streams.send_offset < qc->streams.send_max_data)
    {
        /* not blocked on MAX_DATA */
        qc->streams.send_max_data = f->max_data;
        return NGX_OK;
    }

    qc->streams.send_max_data = f->max_data;
    node = ngx_rbtree_min(tree->root, tree->sentinel);

    while (node && qc->streams.send_offset < qc->streams.send_max_data) {

        qs = (ngx_quic_stream_t *) node;
        node = ngx_rbtree_next(tree, node);

        if (ngx_quic_stream_flush(qs) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f)
{
    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_data_blocked_frame_t *f)
{
    return ngx_quic_update_max_data(c);
}


ngx_int_t
ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f)
{
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    qs = ngx_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NGX_ERROR;
    }

    if (qs == NGX_QUIC_STREAM_GONE) {
        return NGX_OK;
    }

    return ngx_quic_update_max_stream_data(qs);
}


ngx_int_t
ngx_quic_handle_max_stream_data_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_stream_data_frame_t *f)
{
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    qs = ngx_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NGX_ERROR;
    }

    if (qs == NGX_QUIC_STREAM_GONE) {
        return NGX_OK;
    }

    if (f->limit <= qs->send_max_data) {
        return NGX_OK;
    }

    if (qs->send_offset < qs->send_max_data) {
        /* not blocked on MAX_STREAM_DATA */
        qs->send_max_data = f->limit;
        return NGX_OK;
    }

    qs->send_max_data = f->limit;

    return ngx_quic_stream_flush(qs);
}


ngx_int_t
ngx_quic_handle_reset_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_reset_stream_frame_t *f)
{
    ngx_event_t            *rev;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    qs = ngx_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NGX_ERROR;
    }

    if (qs == NGX_QUIC_STREAM_GONE) {
        return NGX_OK;
    }

    if (qs->recv_state == NGX_QUIC_STREAM_RECV_RESET_RECVD
        || qs->recv_state == NGX_QUIC_STREAM_RECV_RESET_READ)
    {
        return NGX_OK;
    }

    qs->recv_state = NGX_QUIC_STREAM_RECV_RESET_RECVD;

    if (ngx_quic_control_flow(qs, f->final_size) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qs->recv_final_size != (uint64_t) -1
        && qs->recv_final_size != f->final_size)
    {
        qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
        return NGX_ERROR;
    }

    if (qs->recv_last > f->final_size) {
        qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
        return NGX_ERROR;
    }

    qs->recv_final_size = f->final_size;

    if (ngx_quic_update_flow(qs, qs->recv_final_size) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qs->connection == NULL) {
        return ngx_quic_close_stream(qs);
    }

    rev = qs->connection->read;
    rev->error = 1;

    ngx_quic_set_event(rev);

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f)
{
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    qs = ngx_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NGX_ERROR;
    }

    if (qs == NGX_QUIC_STREAM_GONE) {
        return NGX_OK;
    }

    if (ngx_quic_do_reset_stream(qs, f->error_code) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qs->connection == NULL) {
        return ngx_quic_close_stream(qs);
    }

    ngx_quic_set_event(qs->connection->write);

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_max_streams_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_streams_frame_t *f)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (f->bidi) {
        if (qc->streams.server_max_streams_bidi < f->limit) {
            qc->streams.server_max_streams_bidi = f->limit;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic max_streams_bidi:%uL", f->limit);
        }

    } else {
        if (qc->streams.server_max_streams_uni < f->limit) {
            qc->streams.server_max_streams_uni = f->limit;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic max_streams_uni:%uL", f->limit);
        }
    }

    return NGX_OK;
}


void
ngx_quic_handle_stream_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    uint64_t                acked;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    switch (f->type) {

    case NGX_QUIC_FT_RESET_STREAM:

        qs = ngx_quic_find_stream(&qc->streams.tree, f->u.reset_stream.id);
        if (qs == NULL) {
            return;
        }

        qs->send_state = NGX_QUIC_STREAM_SEND_RESET_RECVD;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL ack reset final_size:%uL",
                       qs->id, f->u.reset_stream.final_size);

        break;

    case NGX_QUIC_FT_STREAM:

        qs = ngx_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);
        if (qs == NULL) {
            return;
        }

        acked = qs->acked;
        qs->acked += f->u.stream.length;

        if (f->u.stream.fin) {
            qs->fin_acked = 1;
        }

        if (qs->send_state == NGX_QUIC_STREAM_SEND_DATA_SENT
            && qs->acked == qs->sent && qs->fin_acked)
        {
            qs->send_state = NGX_QUIC_STREAM_SEND_DATA_RECVD;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL ack len:%uL fin:%d unacked:%uL",
                       qs->id, f->u.stream.length, f->u.stream.fin,
                       qs->sent - qs->acked);

        if (qs->connection
            && qs->sent - acked == qc->conf->stream_buffer_size
            && f->u.stream.length > 0)
        {
            ngx_quic_set_event(qs->connection->write);
        }

        break;

    default:
        return;
    }

    if (qs->connection == NULL) {
        ngx_quic_close_stream(qs);
    }
}


static ngx_int_t
ngx_quic_control_flow(ngx_quic_stream_t *qs, uint64_t last)
{
    uint64_t                len;
    ngx_connection_t       *pc;
    ngx_quic_connection_t  *qc;

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (last <= qs->recv_last) {
        return NGX_OK;
    }

    len = last - qs->recv_last;

    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flow control msd:%uL/%uL md:%uL/%uL",
                   qs->id, last, qs->recv_max_data, qc->streams.recv_last + len,
                   qc->streams.recv_max_data);

    qs->recv_last += len;

    if (qs->recv_state == NGX_QUIC_STREAM_RECV_RECV
        && qs->recv_last > qs->recv_max_data)
    {
        qc->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
        return NGX_ERROR;
    }

    qc->streams.recv_last += len;

    if (qc->streams.recv_last > qc->streams.recv_max_data) {
        qc->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_update_flow(ngx_quic_stream_t *qs, uint64_t last)
{
    uint64_t                len;
    ngx_connection_t       *pc;
    ngx_quic_connection_t  *qc;

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (last <= qs->recv_offset) {
        return NGX_OK;
    }

    len = last - qs->recv_offset;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flow update %uL", qs->id, last);

    qs->recv_offset += len;

    if (qs->recv_max_data <= qs->recv_offset + qs->recv_window / 2) {
        if (ngx_quic_update_max_stream_data(qs) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    qc->streams.recv_offset += len;

    if (qc->streams.recv_max_data
        <= qc->streams.recv_offset + qc->streams.recv_window / 2)
    {
        if (ngx_quic_update_max_data(pc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_update_max_stream_data(ngx_quic_stream_t *qs)
{
    uint64_t                recv_max_data;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (qs->recv_state != NGX_QUIC_STREAM_RECV_RECV) {
        return NGX_OK;
    }

    recv_max_data = qs->recv_offset + qs->recv_window;

    if (qs->recv_max_data == recv_max_data) {
        return NGX_OK;
    }

    qs->recv_max_data = recv_max_data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flow update msd:%uL",
                   qs->id, qs->recv_max_data);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = qs->id;
    frame->u.max_stream_data.limit = qs->recv_max_data;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_update_max_data(ngx_connection_t *c)
{
    uint64_t                recv_max_data;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    recv_max_data = qc->streams.recv_offset + qc->streams.recv_window;

    if (qc->streams.recv_max_data == recv_max_data) {
        return NGX_OK;
    }

    qc->streams.recv_max_data = recv_max_data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flow update md:%uL", qc->streams.recv_max_data);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_MAX_DATA;
    frame->u.max_data.max_data = qc->streams.recv_max_data;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static void
ngx_quic_set_event(ngx_event_t *ev)
{
    ev->ready = 1;

    if (ev->active) {
        ngx_post_event(ev, &ngx_posted_events);
    }
}
