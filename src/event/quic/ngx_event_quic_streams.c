
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_STREAM_GONE     (void *) -1


static ngx_quic_stream_t *ngx_quic_create_client_stream(ngx_connection_t *c,
    uint64_t id);
static ngx_quic_stream_t *ngx_quic_create_stream(ngx_connection_t *c,
    uint64_t id);
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
    ngx_event_t        *rev, *wev;
    ngx_rbtree_t       *tree;
    ngx_rbtree_node_t  *node;
    ngx_quic_stream_t  *qs;

#if (NGX_DEBUG)
    ngx_uint_t          ns;
#endif

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

    wev = c->write;
    wev->error = 1;
    wev->ready = 1;

    return NGX_OK;
}


static ngx_quic_stream_t *
ngx_quic_create_client_stream(ngx_connection_t *c, uint64_t id)
{
    uint64_t                min_id;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL is new", id);

    qc = ngx_quic_get_connection(c);

    if (qc->shutdown) {
        return NGX_QUIC_STREAM_GONE;
    }

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

    for ( /* void */ ; min_id < id; min_id += 0x04) {

        qs = ngx_quic_create_stream(c, min_id);
        if (qs == NULL) {
            return NULL;
        }

        qs->connection->listening->handler(qs->connection);

        if (qc->shutdown) {
            return NGX_QUIC_STREAM_GONE;
        }
    }

    return ngx_quic_create_stream(c, id);
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

    sc = ngx_get_connection(-1, log);
    if (sc == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    qs->connection = sc;

    sc->quic = qs;
    sc->type = SOCK_STREAM;
    sc->pool = pool;
    sc->ssl = c->ssl;
    sc->sockaddr = c->sockaddr;
    sc->listening = c->listening;
    sc->addr_text = c->addr_text;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;
    sc->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    sc->recv = ngx_quic_stream_recv;
    sc->send = ngx_quic_stream_send;
    sc->send_chain = ngx_quic_stream_send_chain;

    sc->read->log = log;
    sc->write->log = log;

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


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t             len, n;
    ngx_buf_t          *b;
    ngx_chain_t        *cl, **ll;
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

    len = 0;
    cl = qs->in;

    for (ll = &cl; *ll; ll = &(*ll)->next) {
        b = (*ll)->buf;

        if (b->sync) {
            /* hole */
            break;
        }

        n = ngx_min(b->last - b->pos, (ssize_t) size);
        buf = ngx_cpymem(buf, b->pos, n);

        len += n;
        size -= n;
        b->pos += n;

        if (b->pos != b->last) {
            break;
        }
    }

    qs->in = *ll;
    *ll = NULL;

    ngx_quic_free_bufs(pc, cl);

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
    size_t                  n, flow;
    ngx_event_t            *wev;
    ngx_chain_t            *cl;
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

    n = (limit && (size_t) limit < flow) ? (size_t) limit : flow;

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_CHAIN_ERROR;
    }

    frame->data = ngx_quic_copy_chain(pc, in, n);
    if (frame->data == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    for (n = 0, cl = frame->data; cl; cl = cl->next) {
        n += ngx_buf_size(cl->buf);
    }

    while (in && ngx_buf_size(in->buf) == 0) {
        in = in->next;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM6; /* OFF=1 LEN=1 FIN=0 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 0;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = n;

    c->sent += n;
    qc->streams.sent += n;

    ngx_quic_queue_frame(qc, frame);

    wev->ready = (n < flow) ? 1 : 0;

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

    size = NGX_QUIC_STREAM_BUFSIZE;
    sent = c->sent;
    unacked = sent - qs->acked;

    if (qc->streams.send_max_data == 0) {
        qc->streams.send_max_data = qc->ctp.initial_max_data;
    }

    if (unacked >= NGX_QUIC_STREAM_BUFSIZE) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit buffer size");
        return 0;
    }

    if (unacked + size > NGX_QUIC_STREAM_BUFSIZE) {
        size = NGX_QUIC_STREAM_BUFSIZE - unacked;
    }

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

    if (qc->closing) {
        /* schedule handler call to continue ngx_quic_close_connection() */
        ngx_post_event(pc->read, &ngx_posted_events);
        return;
    }

    if (qc->error) {
        goto done;
    }

    c->read->pending_eof = 1;

    (void) ngx_quic_update_flow(c, qs->recv_last);

    if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0
        || (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0)
    {
        if (!c->read->pending_eof && !c->read->error) {
            frame = ngx_quic_alloc_frame(pc);
            if (frame == NULL) {
                goto done;
            }

            frame->level = ssl_encryption_application;
            frame->type = NGX_QUIC_FT_STOP_SENDING;
            frame->u.stop_sending.id = qs->id;
            frame->u.stop_sending.error_code = 0x100; /* HTTP/3 no error */

            ngx_quic_queue_frame(qc, frame);
        }
    }

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

        if (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
            /* do not send fin for client unidirectional streams */
            goto done;
        }
    }

    if (c->write->error) {
        goto done;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL send fin", qs->id);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        goto done;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM7; /* OFF=1 LEN=1 FIN=1 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 1;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = 0;

    ngx_quic_queue_frame(qc, frame);

done:

    (void) ngx_quic_output(pc);

    if (qc->shutdown) {
        ngx_quic_shutdown_quic(pc);
    }
}


ngx_int_t
ngx_quic_handle_stream_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    uint64_t                  last;
    ngx_pool_t               *pool;
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

    qs = ngx_quic_find_stream(&qc->streams.tree, f->stream_id);

    if (qs == NULL) {
        qs = ngx_quic_create_client_stream(c, f->stream_id);

        if (qs == NULL) {
            return NGX_ERROR;
        }

        if (qs == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = qs->connection;

        if (ngx_quic_control_flow(sc, last) != NGX_OK) {
            goto cleanup;
        }

        if (f->fin) {
            sc->read->pending_eof = 1;
            qs->final_size = last;
        }

        if (f->offset == 0) {
            sc->read->ready = 1;
        }

        if (ngx_quic_order_bufs(c, &qs->in, frame->data, f->offset) != NGX_OK) {
            goto cleanup;
        }

        sc->listening->handler(sc);

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

    if (ngx_quic_order_bufs(c, &qs->in, frame->data,
                            f->offset - qs->recv_offset)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (f->offset == qs->recv_offset) {
        rev->ready = 1;

        if (rev->active) {
            rev->handler(rev);
        }
    }

    return NGX_OK;

cleanup:

    pool = sc->pool;

    ngx_close_connection(sc);
    ngx_destroy_pool(pool);

    return NGX_ERROR;
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

    if (qc->streams.sent >= qc->streams.send_max_data) {

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
ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f)
{
    uint64_t                limit;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    qs = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (qs == NULL) {
        qs = ngx_quic_create_client_stream(c, f->id);

        if (qs == NULL) {
            return NGX_ERROR;
        }

        if (qs == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        limit = qs->recv_max_data;

        qs->connection->listening->handler(qs->connection);

    } else {
        limit = qs->recv_max_data;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = f->id;
    frame->u.max_stream_data.limit = limit;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
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

    qs = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (qs == NULL) {
        qs = ngx_quic_create_client_stream(c, f->id);

        if (qs == NULL) {
            return NGX_ERROR;
        }

        if (qs == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        if (f->limit > qs->send_max_data) {
            qs->send_max_data = f->limit;
        }

        qs->connection->listening->handler(qs->connection);

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
    ngx_pool_t             *pool;
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

    qs = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (qs == NULL) {
        qs = ngx_quic_create_client_stream(c, f->id);

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
            goto cleanup;
        }

        qs->final_size = f->final_size;

        if (ngx_quic_update_flow(sc, qs->final_size) != NGX_OK) {
            goto cleanup;
        }

        sc->listening->handler(sc);

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
        rev->handler(rev);
    }

    return NGX_OK;

cleanup:

    pool = sc->pool;

    ngx_close_connection(sc);
    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


ngx_int_t
ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f)
{
    ngx_event_t            *wev;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    qs = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (qs == NULL) {
        qs = ngx_quic_create_client_stream(c, f->id);

        if (qs == NULL) {
            return NGX_ERROR;
        }

        if (qs == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = qs->connection;

        wev = sc->write;
        wev->error = 1;
        wev->ready = 1;

        sc->listening->handler(sc);

        return NGX_OK;
    }

    wev = qs->connection->write;
    wev->error = 1;
    wev->ready = 1;

    if (wev->active) {
        wev->handler(wev);
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

    if (unacked >= NGX_QUIC_STREAM_BUFSIZE && wev->active) {
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
    ngx_quic_frame_t       *frame;
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
        qs->recv_max_data = qs->recv_offset + qs->recv_window;

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
    }

    qc->streams.recv_offset += len;

    if (qc->streams.recv_max_data
        <= qc->streams.recv_offset + qc->streams.recv_window / 2)
    {
        qc->streams.recv_max_data = qc->streams.recv_offset
                                    + qc->streams.recv_window;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                       "quic flow update md:%uL", qc->streams.recv_max_data);

        frame = ngx_quic_alloc_frame(pc);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_DATA;
        frame->u.max_data.max_data = qc->streams.recv_max_data;

        ngx_quic_queue_frame(qc, frame);
    }

    return NGX_OK;
}
