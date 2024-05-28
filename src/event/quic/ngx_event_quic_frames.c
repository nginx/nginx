
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_BUFFER_SIZE  4096

#define ngx_quic_buf_refs(b)         (b)->shadow->num
#define ngx_quic_buf_inc_refs(b)     ngx_quic_buf_refs(b)++
#define ngx_quic_buf_dec_refs(b)     ngx_quic_buf_refs(b)--
#define ngx_quic_buf_set_refs(b, v)  ngx_quic_buf_refs(b) = v


static ngx_buf_t *ngx_quic_alloc_buf(ngx_connection_t *c);
static void ngx_quic_free_buf(ngx_connection_t *c, ngx_buf_t *b);
static ngx_buf_t *ngx_quic_clone_buf(ngx_connection_t *c, ngx_buf_t *b);
static ngx_int_t ngx_quic_split_chain(ngx_connection_t *c, ngx_chain_t *cl,
    off_t offset);


static ngx_buf_t *
ngx_quic_alloc_buf(ngx_connection_t *c)
{
    u_char                 *p;
    ngx_buf_t              *b;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    b = qc->free_bufs;

    if (b) {
        qc->free_bufs = b->shadow;
        p = b->start;

    } else {
        b = qc->free_shadow_bufs;

        if (b) {
            qc->free_shadow_bufs = b->shadow;

#ifdef NGX_QUIC_DEBUG_ALLOC
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic use shadow buffer n:%ui %ui",
                           ++qc->nbufs, --qc->nshadowbufs);
#endif

        } else {
            b = ngx_palloc(c->pool, sizeof(ngx_buf_t));
            if (b == NULL) {
                return NULL;
            }

#ifdef NGX_QUIC_DEBUG_ALLOC
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic new buffer n:%ui", ++qc->nbufs);
#endif
        }

        p = ngx_pnalloc(c->pool, NGX_QUIC_BUFFER_SIZE);
        if (p == NULL) {
            return NULL;
        }
    }

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic alloc buffer %p", b);
#endif

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->tag = (ngx_buf_tag_t) &ngx_quic_alloc_buf;
    b->temporary = 1;
    b->shadow = b;

    b->start = p;
    b->pos = p;
    b->last = p;
    b->end = p + NGX_QUIC_BUFFER_SIZE;

    ngx_quic_buf_set_refs(b, 1);

    return b;
}


static void
ngx_quic_free_buf(ngx_connection_t *c, ngx_buf_t *b)
{
    ngx_buf_t              *shadow;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_quic_buf_dec_refs(b);

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free buffer %p r:%ui",
                   b, (ngx_uint_t) ngx_quic_buf_refs(b));
#endif

    shadow = b->shadow;

    if (ngx_quic_buf_refs(b) == 0) {
        shadow->shadow = qc->free_bufs;
        qc->free_bufs = shadow;
    }

    if (b != shadow) {
        b->shadow = qc->free_shadow_bufs;
        qc->free_shadow_bufs = b;
    }

}


static ngx_buf_t *
ngx_quic_clone_buf(ngx_connection_t *c, ngx_buf_t *b)
{
    ngx_buf_t              *nb;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    nb = qc->free_shadow_bufs;

    if (nb) {
        qc->free_shadow_bufs = nb->shadow;

    } else {
        nb = ngx_palloc(c->pool, sizeof(ngx_buf_t));
        if (nb == NULL) {
            return NULL;
        }

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic new shadow buffer n:%ui", ++qc->nshadowbufs);
#endif
    }

    *nb = *b;

    ngx_quic_buf_inc_refs(b);

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clone buffer %p %p r:%ui",
                   b, nb, (ngx_uint_t) ngx_quic_buf_refs(b));
#endif

    return nb;
}


static ngx_int_t
ngx_quic_split_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t offset)
{
    ngx_buf_t    *b, *tb;
    ngx_chain_t  *tail;

    b = cl->buf;

    tail = ngx_alloc_chain_link(c->pool);
    if (tail == NULL) {
        return NGX_ERROR;
    }

    tb = ngx_quic_clone_buf(c, b);
    if (tb == NULL) {
        return NGX_ERROR;
    }

    tail->buf = tb;

    tb->pos += offset;

    b->last = tb->pos;
    b->last_buf = 0;

    tail->next = cl->next;
    cl->next = tail;

    return NGX_OK;
}


ngx_quic_frame_t *
ngx_quic_alloc_frame(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->free_frames)) {

        q = ngx_queue_head(&qc->free_frames);
        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(&frame->queue);

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse frame n:%ui", qc->nframes);
#endif

    } else if (qc->nframes < 10000) {
        frame = ngx_palloc(c->pool, sizeof(ngx_quic_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        ++qc->nframes;

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic alloc frame n:%ui", qc->nframes);
#endif

    } else {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic flood detected");
        return NULL;
    }

    ngx_memzero(frame, sizeof(ngx_quic_frame_t));

    return frame;
}


void
ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (frame->data) {
        ngx_quic_free_chain(c, frame->data);
    }

    ngx_queue_insert_head(&qc->free_frames, &frame->queue);

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free frame n:%ui", qc->nframes);
#endif
}


void
ngx_quic_free_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    ngx_chain_t  *cl;

    while (in) {
        cl = in;
        in = in->next;

        ngx_quic_free_buf(c, cl->buf);
        ngx_free_chain(c->pool, cl);
    }
}


void
ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames)
{
    ngx_queue_t       *q;
    ngx_quic_frame_t  *f;

    do {
        q = ngx_queue_head(frames);

        if (q == ngx_queue_sentinel(frames)) {
            break;
        }

        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_quic_free_frame(c, f);
    } while (1);
}


void
ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame)
{
    ngx_quic_send_ctx_t  *ctx;

    ctx = ngx_quic_get_send_ctx(qc, frame->level);

    ngx_queue_insert_tail(&ctx->frames, &frame->queue);

    frame->len = ngx_quic_create_frame(NULL, frame);
    /* always succeeds */

    if (qc->closing) {
        return;
    }

    ngx_post_event(&qc->push, &ngx_posted_events);
}


ngx_int_t
ngx_quic_split_frame(ngx_connection_t *c, ngx_quic_frame_t *f, size_t len)
{
    size_t                     shrink;
    ngx_chain_t               *out;
    ngx_quic_frame_t          *nf;
    ngx_quic_buffer_t          qb;
    ngx_quic_ordered_frame_t  *of, *onf;

    switch (f->type) {
    case NGX_QUIC_FT_CRYPTO:
    case NGX_QUIC_FT_STREAM:
        break;

    default:
        return NGX_DECLINED;
    }

    if ((size_t) f->len <= len) {
        return NGX_OK;
    }

    shrink = f->len - len;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic split frame now:%uz need:%uz shrink:%uz",
                   f->len, len, shrink);

    of = &f->u.ord;

    if (of->length <= shrink) {
        return NGX_DECLINED;
    }

    of->length -= shrink;
    f->len = ngx_quic_create_frame(NULL, f);

    if ((size_t) f->len > len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "could not split QUIC frame");
        return NGX_ERROR;
    }

    ngx_memzero(&qb, sizeof(ngx_quic_buffer_t));
    qb.chain = f->data;

    out = ngx_quic_read_buffer(c, &qb, of->length);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    f->data = out;

    nf = ngx_quic_alloc_frame(c);
    if (nf == NULL) {
        return NGX_ERROR;
    }

    *nf = *f;
    onf = &nf->u.ord;
    onf->offset += of->length;
    onf->length = shrink;
    nf->len = ngx_quic_create_frame(NULL, nf);
    nf->data = qb.chain;

    if (f->type == NGX_QUIC_FT_STREAM) {
        f->u.stream.fin = 0;
    }

    ngx_queue_insert_after(&f->queue, &nf->queue);

    return NGX_OK;
}


ngx_chain_t *
ngx_quic_copy_buffer(ngx_connection_t *c, u_char *data, size_t len)
{
    ngx_buf_t          buf;
    ngx_chain_t        cl, *out;
    ngx_quic_buffer_t  qb;

    ngx_memzero(&buf, sizeof(ngx_buf_t));

    buf.pos = data;
    buf.last = buf.pos + len;
    buf.temporary = 1;

    cl.buf = &buf;
    cl.next = NULL;

    ngx_memzero(&qb, sizeof(ngx_quic_buffer_t));

    if (ngx_quic_write_buffer(c, &qb, &cl, len, 0) == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    out = ngx_quic_read_buffer(c, &qb, len);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    ngx_quic_free_buffer(c, &qb);

    return out;
}


ngx_chain_t *
ngx_quic_read_buffer(ngx_connection_t *c, ngx_quic_buffer_t *qb, uint64_t limit)
{
    uint64_t      n;
    ngx_buf_t    *b;
    ngx_chain_t  *out, **ll;

    out = qb->chain;

    for (ll = &out; *ll; ll = &(*ll)->next) {
        b = (*ll)->buf;

        if (b->sync) {
            /* hole */
            break;
        }

        if (limit == 0) {
            break;
        }

        n = b->last - b->pos;

        if (n > limit) {
            if (ngx_quic_split_chain(c, *ll, limit) != NGX_OK) {
                return NGX_CHAIN_ERROR;
            }

            n = limit;
        }

        limit -= n;
        qb->offset += n;
    }

    if (qb->offset >= qb->last_offset) {
        qb->last_chain = NULL;
    }

    qb->chain = *ll;
    *ll = NULL;

    return out;
}


void
ngx_quic_skip_buffer(ngx_connection_t *c, ngx_quic_buffer_t *qb,
    uint64_t offset)
{
    size_t        n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    while (qb->chain) {
        if (qb->offset >= offset) {
            break;
        }

        cl = qb->chain;
        b = cl->buf;
        n = b->last - b->pos;

        if (qb->offset + n > offset) {
            n = offset - qb->offset;
            b->pos += n;
            qb->offset += n;
            break;
        }

        qb->offset += n;
        qb->chain = cl->next;

        cl->next = NULL;
        ngx_quic_free_chain(c, cl);
    }

    if (qb->chain == NULL) {
        qb->offset = offset;
    }

    if (qb->offset >= qb->last_offset) {
        qb->last_chain = NULL;
    }
}


ngx_chain_t *
ngx_quic_alloc_chain(ngx_connection_t *c)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_quic_alloc_buf(c);
    if (cl->buf == NULL) {
        return NULL;
    }

    return cl;
}


ngx_chain_t *
ngx_quic_write_buffer(ngx_connection_t *c, ngx_quic_buffer_t *qb,
    ngx_chain_t *in, uint64_t limit, uint64_t offset)
{
    u_char       *p;
    uint64_t      n, base;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, **chain;

    if (qb->last_chain && offset >= qb->last_offset) {
        base = qb->last_offset;
        chain = &qb->last_chain;

    } else {
        base = qb->offset;
        chain = &qb->chain;
    }

    while (in && limit) {

        if (offset < base) {
            n = ngx_min((uint64_t) (in->buf->last - in->buf->pos),
                        ngx_min(base - offset, limit));

            in->buf->pos += n;
            offset += n;
            limit -= n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }

            continue;
        }

        cl = *chain;

        if (cl == NULL) {
            cl = ngx_quic_alloc_chain(c);
            if (cl == NULL) {
                return NGX_CHAIN_ERROR;
            }

            cl->buf->last = cl->buf->end;
            cl->buf->sync = 1; /* hole */
            cl->next = NULL;
            *chain = cl;
        }

        b = cl->buf;
        n = b->last - b->pos;

        if (base + n <= offset) {
            base += n;
            chain = &cl->next;
            continue;
        }

        if (b->sync && offset > base) {
            if (ngx_quic_split_chain(c, cl, offset - base) != NGX_OK) {
                return NGX_CHAIN_ERROR;
            }

            continue;
        }

        p = b->pos + (offset - base);

        while (in) {

            if (!ngx_buf_in_memory(in->buf) || in->buf->pos == in->buf->last) {
                in = in->next;
                continue;
            }

            if (p == b->last || limit == 0) {
                break;
            }

            n = ngx_min(b->last - p, in->buf->last - in->buf->pos);
            n = ngx_min(n, limit);

            if (b->sync) {
                ngx_memcpy(p, in->buf->pos, n);
                qb->size += n;
            }

            p += n;
            in->buf->pos += n;
            offset += n;
            limit -= n;
        }

        if (b->sync && p == b->last) {
            b->sync = 0;
            continue;
        }

        if (b->sync && p != b->pos) {
            if (ngx_quic_split_chain(c, cl, p - b->pos) != NGX_OK) {
                return NGX_CHAIN_ERROR;
            }

            b->sync = 0;
        }
    }

    qb->last_offset = base;
    qb->last_chain = *chain;

    return in;
}


void
ngx_quic_free_buffer(ngx_connection_t *c, ngx_quic_buffer_t *qb)
{
    ngx_quic_free_chain(c, qb->chain);

    qb->chain = NULL;
    qb->last_chain = NULL;
}


#if (NGX_DEBUG)

void
ngx_quic_log_frame(ngx_log_t *log, ngx_quic_frame_t *f, ngx_uint_t tx)
{
    u_char      *p, *last, *pos, *end;
    ssize_t      n;
    uint64_t     gap, range, largest, smallest;
    ngx_uint_t   i;
    u_char       buf[NGX_MAX_ERROR_STR];

    p = buf;
    last = buf + sizeof(buf);

    switch (f->type) {

    case NGX_QUIC_FT_CRYPTO:
        p = ngx_slprintf(p, last, "CRYPTO len:%uL off:%uL",
                         f->u.crypto.length, f->u.crypto.offset);

#ifdef NGX_QUIC_DEBUG_FRAMES
        {
            ngx_chain_t  *cl;

            p = ngx_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = ngx_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NGX_QUIC_FT_PADDING:
        p = ngx_slprintf(p, last, "PADDING");
        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        p = ngx_slprintf(p, last, "ACK n:%ui delay:%uL ",
                         f->u.ack.range_count, f->u.ack.delay);

        if (f->data) {
            pos = f->data->buf->pos;
            end = f->data->buf->last;

        } else {
            pos = NULL;
            end = NULL;
        }

        largest = f->u.ack.largest;
        smallest = f->u.ack.largest - f->u.ack.first_range;

        if (largest == smallest) {
            p = ngx_slprintf(p, last, "%uL", largest);

        } else {
            p = ngx_slprintf(p, last, "%uL-%uL", largest, smallest);
        }

        for (i = 0; i < f->u.ack.range_count; i++) {
            n = ngx_quic_parse_ack_range(log, pos, end, &gap, &range);
            if (n == NGX_ERROR) {
                break;
            }

            pos += n;

            largest = smallest - gap - 2;
            smallest = largest - range;

            if (largest == smallest) {
                p = ngx_slprintf(p, last, " %uL", largest);

            } else {
                p = ngx_slprintf(p, last, " %uL-%uL", largest, smallest);
            }
        }

        if (f->type == NGX_QUIC_FT_ACK_ECN) {
            p = ngx_slprintf(p, last, " ECN counters ect0:%uL ect1:%uL ce:%uL",
                             f->u.ack.ect0, f->u.ack.ect1, f->u.ack.ce);
        }
        break;

    case NGX_QUIC_FT_PING:
        p = ngx_slprintf(p, last, "PING");
        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        p = ngx_slprintf(p, last,
                         "NEW_CONNECTION_ID seq:%uL retire:%uL len:%ud",
                         f->u.ncid.seqnum, f->u.ncid.retire, f->u.ncid.len);
        break;

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        p = ngx_slprintf(p, last, "RETIRE_CONNECTION_ID seqnum:%uL",
                         f->u.retire_cid.sequence_number);
        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        p = ngx_slprintf(p, last, "CONNECTION_CLOSE%s err:%ui",
                         f->type == NGX_QUIC_FT_CONNECTION_CLOSE ? "" : "_APP",
                         f->u.close.error_code);

        if (f->u.close.reason.len) {
            p = ngx_slprintf(p, last, " %V", &f->u.close.reason);
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {
            p = ngx_slprintf(p, last, " ft:%ui", f->u.close.frame_type);
        }

        break;

    case NGX_QUIC_FT_STREAM:
        p = ngx_slprintf(p, last, "STREAM id:0x%xL", f->u.stream.stream_id);

        if (f->u.stream.off) {
            p = ngx_slprintf(p, last, " off:%uL", f->u.stream.offset);
        }

        if (f->u.stream.len) {
            p = ngx_slprintf(p, last, " len:%uL", f->u.stream.length);
        }

        if (f->u.stream.fin) {
            p = ngx_slprintf(p, last, " fin:1");
        }

#ifdef NGX_QUIC_DEBUG_FRAMES
        {
            ngx_chain_t  *cl;

            p = ngx_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = ngx_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NGX_QUIC_FT_MAX_DATA:
        p = ngx_slprintf(p, last, "MAX_DATA max_data:%uL on recv",
                         f->u.max_data.max_data);
        break;

    case NGX_QUIC_FT_RESET_STREAM:
        p = ngx_slprintf(p, last, "RESET_STREAM"
                        " id:0x%xL error_code:0x%xL final_size:0x%xL",
                        f->u.reset_stream.id, f->u.reset_stream.error_code,
                        f->u.reset_stream.final_size);
        break;

    case NGX_QUIC_FT_STOP_SENDING:
        p = ngx_slprintf(p, last, "STOP_SENDING id:0x%xL err:0x%xL",
                         f->u.stop_sending.id, f->u.stop_sending.error_code);
        break;

    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:
        p = ngx_slprintf(p, last, "STREAMS_BLOCKED limit:%uL bidi:%ui",
                         f->u.streams_blocked.limit, f->u.streams_blocked.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:
        p = ngx_slprintf(p, last, "MAX_STREAMS limit:%uL bidi:%ui",
                         f->u.max_streams.limit, f->u.max_streams.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAM_DATA:
        p = ngx_slprintf(p, last, "MAX_STREAM_DATA id:0x%xL limit:%uL",
                         f->u.max_stream_data.id, f->u.max_stream_data.limit);
        break;


    case NGX_QUIC_FT_DATA_BLOCKED:
        p = ngx_slprintf(p, last, "DATA_BLOCKED limit:%uL",
                         f->u.data_blocked.limit);
        break;

    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:
        p = ngx_slprintf(p, last, "STREAM_DATA_BLOCKED id:0x%xL limit:%uL",
                         f->u.stream_data_blocked.id,
                         f->u.stream_data_blocked.limit);
        break;

    case NGX_QUIC_FT_PATH_CHALLENGE:
        p = ngx_slprintf(p, last, "PATH_CHALLENGE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NGX_QUIC_FT_PATH_RESPONSE:
        p = ngx_slprintf(p, last, "PATH_RESPONSE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NGX_QUIC_FT_NEW_TOKEN:
        p = ngx_slprintf(p, last, "NEW_TOKEN");

#ifdef NGX_QUIC_DEBUG_FRAMES
        {
            ngx_chain_t  *cl;

            p = ngx_slprintf(p, last, " token:");

            for (cl = f->data; cl; cl = cl->next) {
                p = ngx_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        p = ngx_slprintf(p, last, "HANDSHAKE DONE");
        break;

    default:
        p = ngx_slprintf(p, last, "unknown type 0x%xi", f->type);
        break;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, log, 0, "quic frame %s %s:%uL %*s",
                   tx ? "tx" : "rx", ngx_quic_level_name(f->level), f->pnum,
                   p - buf, buf);
}

#endif
