
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_STREAM_GONE     (void *) -1


static ngx_int_t ngx_quic_shutdown_stream_send(ngx_connection_t *c);
static ngx_int_t ngx_quic_shutdown_stream_recv(ngx_connection_t *c);
static ngx_quic_stream_t *ngx_quic_get_stream(ngx_connection_t *c, uint64_t id);
static ngx_int_t ngx_quic_reject_stream(ngx_connection_t *c, uint64_t id);
static void ngx_quic_init_stream_handler(ngx_event_t *ev);
static void ngx_quic_init_streams_handler(ngx_connection_t *c);
static ngx_quic_stream_t *ngx_quic_create_stream(ngx_connection_t *c,
    uint64_t id);
static void ngx_quic_empty_handler(ngx_event_t *ev);
static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static size_t ngx_quic_max_stream_flow(ngx_connection_t *c);
static void ngx_quic_stream_cleanup_handler(void *data);
static ngx_int_t ngx_quic_control_flow(ngx_connection_t *c, uint64_t last);
static ngx_int_t ngx_quic_update_flow(ngx_connection_t *c, uint64_t last);
static ngx_int_t ngx_quic_update_max_stream_data(ngx_connection_t *c);
static ngx_int_t ngx_quic_update_max_data(ngx_connection_t *c);


ngx_connection_t *
ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi)
{
    uint64_t                id;
    ngx_quic_stream_t      *qs, *nqs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    qc = ngx_quic_get_connection(qs->parent);

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

    nqs = ngx_quic_create_stream(qs->parent, id);
    if (nqs == NULL) {
        return NULL;
    }

    return nqs->connection;
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
    ngx_queue_t        *q;
    ngx_event_t        *rev, *wev;
    ngx_rbtree_t       *tree;
    ngx_rbtree_node_t  *node;
    ngx_quic_stream_t  *qs;

#if (NGX_DEBUG)
    ngx_uint_t          ns;
#endif

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

#if (NGX_DEBUG)
    ns = 0;
#endif

    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        qs = (ngx_quic_stream_t *) node;

        rev = qs->connection->read;
        rev->error = 1;
        rev->ready = 1;

        wev = qs->connection->write;
        wev->error = 1;
        wev->ready = 1;

        ngx_post_event(rev, &ngx_posted_events);

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

#if (NGX_DEBUG)
        ns++;
#endif
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection has %ui active streams", ns);

    return NGX_AGAIN;
}


ngx_int_t
ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err)
{
    ngx_event_t            *wev;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    wev = c->write;

    if (wev->error) {
        return NGX_OK;
    }

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = qs->id;
    frame->u.reset_stream.error_code = err;
    frame->u.reset_stream.final_size = c->sent;

    ngx_quic_queue_frame(qc, frame);

    wev->error = 1;
    wev->ready = 1;

    return NGX_OK;
}


ngx_int_t
ngx_quic_shutdown_stream(ngx_connection_t *c, int how)
{
    ngx_quic_stream_t  *qs;

    qs = c->quic;

    if (how == NGX_RDWR_SHUTDOWN || how == NGX_WRITE_SHUTDOWN) {
        if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED)
            || (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0)
        {
            if (ngx_quic_shutdown_stream_send(c) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    if (how == NGX_RDWR_SHUTDOWN || how == NGX_READ_SHUTDOWN) {
        if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0
            || (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0)
        {
            if (ngx_quic_shutdown_stream_recv(c) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_shutdown_stream_send(ngx_connection_t *c)
{
    ngx_event_t            *wev;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    wev = c->write;

    if (wev->error) {
        return NGX_OK;
    }

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL send shutdown", qs->id);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM;
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 1;

    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = 0;

    ngx_quic_queue_frame(qc, frame);

    wev->error = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_shutdown_stream_recv(ngx_connection_t *c)
{
    ngx_event_t            *rev;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    rev = c->read;

    if (rev->pending_eof || rev->error) {
        return NGX_OK;
    }

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (qc->conf->stream_close_code == 0) {
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv shutdown", qs->id);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = qs->id;
    frame->u.stop_sending.error_code = qc->conf->stream_close_code;

    ngx_quic_queue_frame(qc, frame);

    rev->error = 1;

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

    ngx_quic_init_streams_handler(c);

    return NGX_OK;
}


static void
ngx_quic_init_streams_handler(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic init streams");

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->streams.uninitialized);
         q != ngx_queue_sentinel(&qc->streams.uninitialized);
         q = ngx_queue_next(q))
    {
        qs = ngx_queue_data(q, ngx_quic_stream_t, queue);
        ngx_post_event(qs->connection->read, &ngx_posted_events);
    }

    qc->streams.initialized = 1;
}


static ngx_quic_stream_t *
ngx_quic_create_stream(ngx_connection_t *c, uint64_t id)
{
    ngx_log_t              *log;
    ngx_pool_t             *pool;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *qs;
    ngx_pool_cleanup_t     *cln;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL create", id);

    qc = ngx_quic_get_connection(c);

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        return NULL;
    }

    qs = ngx_pcalloc(pool, sizeof(ngx_quic_stream_t));
    if (qs == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    qs->node.key = id;
    qs->parent = c;
    qs->id = id;
    qs->final_size = (uint64_t) -1;

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sc = ngx_get_connection(c->fd, log);
    if (sc == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    qs->connection = sc;

    sc->quic = qs;
    sc->shared = 1;
    sc->type = SOCK_STREAM;
    sc->pool = pool;
    sc->ssl = c->ssl;
    sc->sockaddr = c->sockaddr;
    sc->listening = c->listening;
    sc->addr_text = c->addr_text;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;
    sc->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    sc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    sc->recv = ngx_quic_stream_recv;
    sc->send = ngx_quic_stream_send;
    sc->send_chain = ngx_quic_stream_send_chain;

    sc->read->log = log;
    sc->write->log = log;

    sc->read->handler = ngx_quic_empty_handler;
    sc->write->handler = ngx_quic_empty_handler;

    log->connection = sc->number;

    if ((id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0
        || (id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        sc->write->ready = 1;
    }

    if (id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_uni;

        } else {
            qs->recv_max_data = qc->tp.initial_max_stream_data_uni;
        }

    } else {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_remote;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_local;

        } else {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_local;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_remote;
        }
    }

    qs->recv_window = qs->recv_max_data;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        ngx_close_connection(sc);
        ngx_destroy_pool(pool);
        return NULL;
    }

    cln->handler = ngx_quic_stream_cleanup_handler;
    cln->data = sc;

    ngx_rbtree_insert(&qc->streams.tree, &qs->node);

    return qs;
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

    if (rev->error) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv eof:%d buf:%uz",
                   qs->id, rev->pending_eof, size);

    if (qs->in == NULL || qs->in->buf->sync) {
        rev->ready = 0;

        if (qs->recv_offset == qs->final_size) {
            rev->eof = 1;
            return 0;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv() not ready", qs->id);
        return NGX_AGAIN;
    }

    in = ngx_quic_read_chain(pc, &qs->in, size);
    if (in == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    len = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        len += b->last - b->pos;
        buf = ngx_cpymem(buf, b->pos, b->last - b->pos);
    }

    ngx_quic_free_bufs(pc, in);

    if (qs->in == NULL) {
        rev->ready = rev->pending_eof;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv len:%z", qs->id, len);

    if (ngx_quic_update_flow(c, qs->recv_offset + len) != NGX_OK) {
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
    off_t                   n, flow;
    ngx_event_t            *wev;
    ngx_chain_t            *out, *cl;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);
    wev = c->write;

    if (wev->error) {
        return NGX_CHAIN_ERROR;
    }

    flow = ngx_quic_max_stream_flow(c);
    if (flow == 0) {
        wev->ready = 0;
        return in;
    }

    if (limit == 0 || limit > flow) {
        limit = flow;
    }

    n = 0;

    for (cl = in; cl; cl = cl->next) {
        n += cl->buf->last - cl->buf->pos;
        if (n >= limit) {
            n = limit;
            break;
        }
    }

    in = ngx_quic_write_chain(pc, &qs->out, in, n, 0);
    if (in == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    out = ngx_quic_read_chain(pc, &qs->out, n);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_CHAIN_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM;
    frame->data = out;
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 0;

    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = n;

    c->sent += n;
    qc->streams.sent += n;

    ngx_quic_queue_frame(qc, frame);

    if (in) {
        wev->ready = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send_chain sent:%uz", n);

    return in;
}


static size_t
ngx_quic_max_stream_flow(ngx_connection_t *c)
{
    size_t                  size;
    uint64_t                sent, unacked;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    qc = ngx_quic_get_connection(qs->parent);

    size = qc->conf->stream_buffer_size;
    sent = c->sent;
    unacked = sent - qs->acked;

    if (qc->streams.send_max_data == 0) {
        qc->streams.send_max_data = qc->ctp.initial_max_data;
    }

    if (unacked >= size) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit buffer size");
        return 0;
    }

    size -= unacked;

    if (qc->streams.sent >= qc->streams.send_max_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit MAX_DATA");
        return 0;
    }

    if (qc->streams.sent + size > qc->streams.send_max_data) {
        size = qc->streams.send_max_data - qc->streams.sent;
    }

    if (sent >= qs->send_max_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit MAX_STREAM_DATA");
        return 0;
    }

    if (sent + size > qs->send_max_data) {
        size = qs->send_max_data - sent;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send flow:%uz", size);

    return size;
}


static void
ngx_quic_stream_cleanup_handler(void *data)
{
    ngx_connection_t *c = data;

    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL cleanup", qs->id);

    ngx_rbtree_delete(&qc->streams.tree, &qs->node);
    ngx_quic_free_bufs(pc, qs->in);
    ngx_quic_free_bufs(pc, qs->out);

    if (qc->closing) {
        /* schedule handler call to continue ngx_quic_close_connection() */
        ngx_post_event(pc->read, &ngx_posted_events);
        return;
    }

    if (qc->error) {
        goto done;
    }

    (void) ngx_quic_shutdown_stream(c, NGX_RDWR_SHUTDOWN);

    (void) ngx_quic_update_flow(c, qs->recv_last);

    if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0) {
        frame = ngx_quic_alloc_frame(pc);
        if (frame == NULL) {
            goto done;
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

done:

    (void) ngx_quic_output(pc);

    if (qc->shutdown) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }
}


ngx_int_t
ngx_quic_handle_stream_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    uint64_t                  last;
    ngx_event_t              *rev;
    ngx_connection_t         *sc;
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

    sc = qs->connection;

    rev = sc->read;

    if (rev->error) {
        return NGX_OK;
    }

    if (ngx_quic_control_flow(sc, last) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qs->final_size != (uint64_t) -1 && last > qs->final_size) {
        qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
        return NGX_ERROR;
    }

    if (last <= qs->recv_offset) {
        return NGX_OK;
    }

    if (f->offset < qs->recv_offset) {
        ngx_quic_trim_bufs(frame->data, qs->recv_offset - f->offset);
        f->offset = qs->recv_offset;
    }

    if (f->fin) {
        if (qs->final_size != (uint64_t) -1 && qs->final_size != last) {
            qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
            return NGX_ERROR;
        }

        if (qs->recv_last > last) {
            qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
            return NGX_ERROR;
        }

        rev->pending_eof = 1;
        qs->final_size = last;
    }

    if (ngx_quic_write_chain(c, &qs->in, frame->data, f->length,
                             f->offset - qs->recv_offset)
        == NGX_CHAIN_ERROR)
    {
        return NGX_ERROR;
    }

    if (f->offset == qs->recv_offset) {
        rev->ready = 1;

        if (rev->active) {
            ngx_post_event(rev, &ngx_posted_events);
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_max_data_frame(ngx_connection_t *c,
    ngx_quic_max_data_frame_t *f)
{
    ngx_event_t            *wev;
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    tree = &qc->streams.tree;

    if (f->max_data <= qc->streams.send_max_data) {
        return NGX_OK;
    }

    if (tree->root != tree->sentinel
        && qc->streams.sent >= qc->streams.send_max_data)
    {

        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            qs = (ngx_quic_stream_t *) node;
            wev = qs->connection->write;

            if (wev->active) {
                wev->ready = 1;
                ngx_post_event(wev, &ngx_posted_events);
            }
        }
    }

    qc->streams.send_max_data = f->max_data;

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

    return ngx_quic_update_max_stream_data(qs->connection);
}


ngx_int_t
ngx_quic_handle_max_stream_data_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_stream_data_frame_t *f)
{
    uint64_t                sent;
    ngx_event_t            *wev;
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

    sent = qs->connection->sent;

    if (sent >= qs->send_max_data) {
        wev = qs->connection->write;

        if (wev->active) {
            wev->ready = 1;
            ngx_post_event(wev, &ngx_posted_events);
        }
    }

    qs->send_max_data = f->limit;

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_reset_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_reset_stream_frame_t *f)
{
    ngx_event_t            *rev;
    ngx_connection_t       *sc;
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

    sc = qs->connection;

    rev = sc->read;
    rev->error = 1;
    rev->ready = 1;

    if (ngx_quic_control_flow(sc, f->final_size) != NGX_OK) {
        return NGX_ERROR;
    }

    if (qs->final_size != (uint64_t) -1 && qs->final_size != f->final_size) {
        qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
        return NGX_ERROR;
    }

    if (qs->recv_last > f->final_size) {
        qc->error = NGX_QUIC_ERR_FINAL_SIZE_ERROR;
        return NGX_ERROR;
    }

    qs->final_size = f->final_size;

    if (ngx_quic_update_flow(sc, qs->final_size) != NGX_OK) {
        return NGX_ERROR;
    }

    if (rev->active) {
        ngx_post_event(rev, &ngx_posted_events);
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f)
{
    ngx_event_t            *wev;
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

    if (ngx_quic_reset_stream(qs->connection, f->error_code) != NGX_OK) {
        return NGX_ERROR;
    }

    wev = qs->connection->write;

    if (wev->active) {
        ngx_post_event(wev, &ngx_posted_events);
    }

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
    uint64_t                sent, unacked;
    ngx_event_t            *wev;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    qs = ngx_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);
    if (qs == NULL) {
        return;
    }

    wev = qs->connection->write;
    sent = qs->connection->sent;
    unacked = sent - qs->acked;

    if (unacked >= qc->conf->stream_buffer_size && wev->active) {
        wev->ready = 1;
        ngx_post_event(wev, &ngx_posted_events);
    }

    qs->acked += f->u.stream.length;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, qs->connection->log, 0,
                   "quic stream ack len:%uL acked:%uL unacked:%uL",
                   f->u.stream.length, qs->acked, sent - qs->acked);
}


static ngx_int_t
ngx_quic_control_flow(ngx_connection_t *c, uint64_t last)
{
    uint64_t                len;
    ngx_event_t            *rev;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    rev = c->read;
    qs = c->quic;
    qc = ngx_quic_get_connection(qs->parent);

    if (last <= qs->recv_last) {
        return NGX_OK;
    }

    len = last - qs->recv_last;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flow control msd:%uL/%uL md:%uL/%uL",
                   last, qs->recv_max_data, qc->streams.recv_last + len,
                   qc->streams.recv_max_data);

    qs->recv_last += len;

    if (!rev->error && qs->recv_last > qs->recv_max_data) {
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
ngx_quic_update_flow(ngx_connection_t *c, uint64_t last)
{
    uint64_t                len;
    ngx_event_t            *rev;
    ngx_connection_t       *pc;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    rev = c->read;
    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    if (last <= qs->recv_offset) {
        return NGX_OK;
    }

    len = last - qs->recv_offset;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flow update %uL", last);

    qs->recv_offset += len;

    if (!rev->pending_eof && !rev->error
        && qs->recv_max_data <= qs->recv_offset + qs->recv_window / 2)
    {
        if (ngx_quic_update_max_stream_data(c) != NGX_OK) {
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
ngx_quic_update_max_stream_data(ngx_connection_t *c)
{
    uint64_t                recv_max_data;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    recv_max_data = qs->recv_offset + qs->recv_window;

    if (qs->recv_max_data == recv_max_data) {
        return NGX_OK;
    }

    qs->recv_max_data = recv_max_data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flow update msd:%uL", qs->recv_max_data);

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


ngx_int_t
ngx_quic_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
{
    if (!rev->active && !rev->ready) {
        rev->active = 1;

    } else if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
        rev->active = 0;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_write_event(ngx_event_t *wev, size_t lowat)
{
    if (!wev->active && !wev->ready) {
        wev->active = 1;

    } else if (wev->active && wev->ready) {
        wev->active = 0;
    }

    return NGX_OK;
}
