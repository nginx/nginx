
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
    uint64_t id, size_t rcvbuf_size);
static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static size_t ngx_quic_max_stream_flow(ngx_connection_t *c);
static void ngx_quic_stream_cleanup_handler(void *data);


ngx_connection_t *
ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi)
{
    size_t                  rcvbuf_size;
    uint64_t                id;
    ngx_quic_stream_t      *qs, *sn;
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
        rcvbuf_size = qc->tp.initial_max_stream_data_bidi_local;

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
        rcvbuf_size = 0;
    }

    sn = ngx_quic_create_stream(qs->parent, id, rcvbuf_size);
    if (sn == NULL) {
        return NULL;
    }

    return sn->c;
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

        rev = qs->c->read;
        rev->error = 1;
        rev->ready = 1;

        wev = qs->c->write;
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
    size_t                  n;
    uint64_t                min_id;
    ngx_quic_stream_t      *sn;
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
        n = qc->tp.initial_max_stream_data_uni;

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
        n = qc->tp.initial_max_stream_data_bidi_remote;
    }

    if (n < NGX_QUIC_STREAM_BUFSIZE) {
        n = NGX_QUIC_STREAM_BUFSIZE;
    }

    /*
     *   2.1.  Stream Types and Identifiers
     *
     *   Within each type, streams are created with numerically increasing
     *   stream IDs.  A stream ID that is used out of order results in all
     *   streams of that type with lower-numbered stream IDs also being
     *   opened.
     */

    for ( /* void */ ; min_id < id; min_id += 0x04) {

        sn = ngx_quic_create_stream(c, min_id, n);
        if (sn == NULL) {
            return NULL;
        }

        sn->c->listening->handler(sn->c);

        if (qc->shutdown) {
            return NGX_QUIC_STREAM_GONE;
        }
    }

    return ngx_quic_create_stream(c, id, n);
}


static ngx_quic_stream_t *
ngx_quic_create_stream(ngx_connection_t *c, uint64_t id, size_t rcvbuf_size)
{
    ngx_log_t              *log;
    ngx_pool_t             *pool;
    ngx_quic_stream_t      *sn;
    ngx_pool_cleanup_t     *cln;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL create", id);

    qc = ngx_quic_get_connection(c);

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        return NULL;
    }

    sn = ngx_pcalloc(pool, sizeof(ngx_quic_stream_t));
    if (sn == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->node.key = id;
    sn->parent = c;
    sn->id = id;

    sn->b = ngx_create_temp_buf(pool, rcvbuf_size);
    if (sn->b == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->fs = ngx_pcalloc(pool, sizeof(ngx_quic_frames_stream_t));
    if (sn->fs == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_queue_init(&sn->fs->frames);

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sn->c = ngx_get_connection(-1, log);
    if (sn->c == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->c->quic = sn;
    sn->c->type = SOCK_STREAM;
    sn->c->pool = pool;
    sn->c->ssl = c->ssl;
    sn->c->sockaddr = c->sockaddr;
    sn->c->listening = c->listening;
    sn->c->addr_text = c->addr_text;
    sn->c->local_sockaddr = c->local_sockaddr;
    sn->c->local_socklen = c->local_socklen;
    sn->c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    sn->c->recv = ngx_quic_stream_recv;
    sn->c->send = ngx_quic_stream_send;
    sn->c->send_chain = ngx_quic_stream_send_chain;

    sn->c->read->log = log;
    sn->c->write->log = log;

    log->connection = sn->c->number;

    if ((id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0
        || (id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        sn->c->write->ready = 1;
    }

    if (id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            sn->send_max_data = qc->ctp.initial_max_stream_data_uni;
        }

    } else {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            sn->send_max_data = qc->ctp.initial_max_stream_data_bidi_remote;
        } else {
            sn->send_max_data = qc->ctp.initial_max_stream_data_bidi_local;
        }
    }

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        ngx_close_connection(sn->c);
        ngx_destroy_pool(pool);
        return NULL;
    }

    cln->handler = ngx_quic_stream_cleanup_handler;
    cln->data = sn->c;

    ngx_rbtree_insert(&qc->streams.tree, &sn->node);

    return sn;
}


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                 len;
    ngx_buf_t              *b;
    ngx_event_t            *rev;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    b = qs->b;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);
    rev = c->read;

    if (rev->error) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream recv id:0x%xL eof:%d avail:%z",
                   qs->id, rev->pending_eof, b->last - b->pos);

    if (b->pos == b->last) {
        rev->ready = 0;

        if (rev->pending_eof) {
            rev->eof = 1;
            return 0;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv() not ready", qs->id);
        return NGX_AGAIN;
    }

    len = ngx_min(b->last - b->pos, (ssize_t) size);

    ngx_memcpy(buf, b->pos, len);

    b->pos += len;
    qc->streams.received += len;

    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
        rev->ready = rev->pending_eof;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv len:%z of size:%uz",
                   qs->id, len, size);

    if (!rev->pending_eof) {
        frame = ngx_quic_alloc_frame(pc);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
        frame->u.max_stream_data.id = qs->id;
        frame->u.max_stream_data.limit = qs->fs->received + (b->pos - b->start)
                                         + (b->end - b->last);

        ngx_quic_queue_frame(qc, frame);
    }

    if ((qc->streams.recv_max_data / 2) < qc->streams.received) {

        frame = ngx_quic_alloc_frame(pc);

        if (frame == NULL) {
            return NGX_ERROR;
        }

        qc->streams.recv_max_data *= 2;

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_DATA;
        frame->u.max_data.max_data = qc->streams.recv_max_data;

        ngx_quic_queue_frame(qc, frame);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv: increased max_data:%uL",
                       qs->id, qc->streams.recv_max_data);
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
    ngx_quic_free_frames(pc, &qs->fs->frames);

    if (qc->closing) {
        /* schedule handler call to continue ngx_quic_close_connection() */
        ngx_post_event(pc->read, &ngx_posted_events);
        return;
    }

    if (qc->error) {
        goto done;
    }

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
    size_t                     window;
    uint64_t                   last;
    ngx_buf_t                 *b;
    ngx_pool_t                *pool;
    ngx_connection_t          *sc;
    ngx_quic_stream_t         *sn;
    ngx_quic_connection_t     *qc;
    ngx_quic_stream_frame_t   *f;
    ngx_quic_frames_stream_t  *fs;

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

    sn = ngx_quic_find_stream(&qc->streams.tree, f->stream_id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->stream_id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = sn->c;
        fs = sn->fs;
        b = sn->b;
        window = b->end - b->last;

        if (last > window) {
            qc->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
            goto cleanup;
        }

        if (ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_stream_input,
                                          sn)
            != NGX_OK)
        {
            goto cleanup;
        }

        sc->listening->handler(sc);

        return NGX_OK;
    }

    fs = sn->fs;
    b = sn->b;
    window = (b->pos - b->start) + (b->end - b->last);

    if (last > fs->received && last - fs->received > window) {
        qc->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
        return NGX_ERROR;
    }

    return ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_stream_input,
                                         sn);

cleanup:

    pool = sc->pool;

    ngx_close_connection(sc);
    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


ngx_int_t
ngx_quic_stream_input(ngx_connection_t *c, ngx_quic_frame_t *frame, void *data)
{
    uint64_t                  id;
    ngx_buf_t                *b;
    ngx_event_t              *rev;
    ngx_chain_t              *cl;
    ngx_quic_stream_t        *sn;
    ngx_quic_connection_t    *qc;
    ngx_quic_stream_frame_t  *f;

    qc = ngx_quic_get_connection(c);
    sn = data;

    f = &frame->u.stream;
    id = f->stream_id;

    b = sn->b;

    if ((size_t) ((b->pos - b->start) + (b->end - b->last)) < f->length) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no space in stream buffer");
        return NGX_ERROR;
    }

    if ((size_t) (b->end - b->last) < f->length) {
        b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
        b->pos = b->start;
    }

    for (cl = frame->data; cl; cl = cl->next) {
        b->last = ngx_cpymem(b->last, cl->buf->pos,
                             cl->buf->last - cl->buf->pos);
    }

    rev = sn->c->read;
    rev->ready = 1;

    if (f->fin) {
        rev->pending_eof = 1;
    }

    if (rev->active) {
        rev->handler(rev);
    }

    /* check if stream was destroyed by handler */
    if (ngx_quic_find_stream(&qc->streams.tree, id) == NULL) {
        return NGX_DONE;
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

    if (qc->streams.sent >= qc->streams.send_max_data) {

        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            qs = (ngx_quic_stream_t *) node;
            wev = qs->c->write;

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
    size_t                  n;
    ngx_buf_t              *b;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        b = sn->b;
        n = b->end - b->last;

        sn->c->listening->handler(sn->c);

    } else {
        b = sn->b;
        n = sn->fs->received + (b->pos - b->start) + (b->end - b->last);
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = f->id;
    frame->u.max_stream_data.limit = n;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_max_stream_data_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_stream_data_frame_t *f)
{
    uint64_t                sent;
    ngx_event_t            *wev;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        if (f->limit > sn->send_max_data) {
            sn->send_max_data = f->limit;
        }

        sn->c->listening->handler(sn->c);

        return NGX_OK;
    }

    if (f->limit <= sn->send_max_data) {
        return NGX_OK;
    }

    sent = sn->c->sent;

    if (sent >= sn->send_max_data) {
        wev = sn->c->write;

        if (wev->active) {
            wev->ready = 1;
            ngx_post_event(wev, &ngx_posted_events);
        }
    }

    sn->send_max_data = f->limit;

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_reset_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_reset_stream_frame_t *f)
{
    ngx_event_t            *rev;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = sn->c;

        rev = sc->read;
        rev->error = 1;
        rev->ready = 1;

        sc->listening->handler(sc);

        return NGX_OK;
    }

    rev = sn->c->read;
    rev->error = 1;
    rev->ready = 1;

    if (rev->active) {
        rev->handler(rev);
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f)
{
    ngx_event_t            *wev;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = sn->c;

        wev = sc->write;
        wev->error = 1;
        wev->ready = 1;

        sc->listening->handler(sc);

        return NGX_OK;
    }

    wev = sn->c->write;
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
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    sn = ngx_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);
    if (sn == NULL) {
        return;
    }

    wev = sn->c->write;
    sent = sn->c->sent;
    unacked = sent - sn->acked;

    if (unacked >= NGX_QUIC_STREAM_BUFSIZE && wev->active) {
        wev->ready = 1;
        ngx_post_event(wev, &ngx_posted_events);
    }

    sn->acked += f->u.stream.length;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, sn->c->log, 0,
                   "quic stream ack len:%uL acked:%uL unacked:%uL",
                   f->u.stream.length, sn->acked, sent - sn->acked);
}
