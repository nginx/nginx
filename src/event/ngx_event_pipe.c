
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe.h>


static ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p);

static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p);
ngx_inline static void ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf);
ngx_inline static void ngx_event_pipe_free_shadow_raw_buf(ngx_chain_t **free,
                                                          ngx_buf_t *buf);
ngx_inline static void ngx_event_pipe_add_free_buf(ngx_chain_t **chain,
                                                   ngx_chain_t *cl);
static ngx_int_t ngx_event_pipe_drain_chains(ngx_event_pipe_t *p);


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, int do_write)
{
    u_int         flags;
    ngx_event_t  *rev, *wev;

    for ( ;; ) {
        if (do_write) {
            if (ngx_event_pipe_write_to_downstream(p) == NGX_ABORT) {
                return NGX_ABORT;
            }
        }

        p->read = 0;
        p->upstream_blocked = 0;

        if (ngx_event_pipe_read_upstream(p) == NGX_ABORT) {
            return NGX_ABORT;
        }

        if (!p->read && !p->upstream_blocked) {
            break;
        }

        do_write = 1;
    }

    if (p->upstream->fd != -1) {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? NGX_CLOSE_EVENT : 0;

        if (ngx_handle_read_event(rev, flags) == NGX_ERROR) {
            return NGX_ABORT;
        }

        if (rev->active) {
            ngx_add_timer(rev, p->read_timeout);
        }
    }

    if (p->downstream->fd != -1) {
        wev = p->downstream->write;
        wev->available = p->send_lowat;
        if (ngx_handle_write_event(wev, NGX_LOWAT_EVENT) == NGX_ERROR) {
            return NGX_ABORT;
        }

        if (wev->active) {
            ngx_add_timer(wev, p->send_timeout);
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p)
{
    int           n, rc, size;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, *tl;

    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe read upstream: %d", p->upstream->read->ready);

    for ( ;; ) {

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {
            break;
        }

        if (p->preread_bufs == NULL && !p->upstream->read->ready) {
            break;
        }

        if (p->preread_bufs) {

            /* use the pre-read bufs if they exist */

            chain = p->preread_bufs;
            p->preread_bufs = NULL;
            n = p->preread_size;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe preread: %d", n);

            if (n) {
                p->read = 1;
            }

        } else {

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a buf on these conditions
             * and not to call ngx_recv_chain().
             */

            if (p->upstream->read->available == 0
                && p->upstream->read->pending_eof)
            {
                p->upstream->read->ready = 0;
                p->upstream->read->eof = 0;
                p->upstream_eof = 1;
                p->read = 1;

#if (HAVE_KQUEUE)
                if (p->upstream->read->kq_errno) {
                    p->upstream->read->error = 1;
                    p->upstream_error = 1;
                    p->upstream_eof = 0;

                    ngx_log_error(NGX_LOG_ERR, p->log,
                                  p->upstream->read->kq_errno,
                                  "readv() failed");
                }
#endif

                break;
            }

            if (p->free_raw_bufs) {

                /* use the free bufs if they exist */

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else if (p->allocated < p->bufs.num) {

                /* allocate a new buf if it's still allowed */

                if (!(b = ngx_create_temp_buf(p->pool, p->bufs.size))) {
                    return NGX_ABORT;
                }

                p->allocated++;

                ngx_alloc_link_and_set_buf(tl, b, p->pool, NGX_ABORT);
                chain = tl;

            } else if (!p->cachable && p->downstream->write->ready) {

                /*
                 * if the bufs are not needed to be saved in a cache and
                 * a downstream is ready then write the bufs to a downstream
                 */

                p->upstream_blocked = 1;

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe downstream ready");

                break;

            } else if (p->cachable
                       || p->temp_file->offset < p->max_temp_file_size)
            {

                /*
                 * if it's allowed then save some bufs from r->in
                 * to a temporary file, and add them to a r->out chain
                 */

                rc = ngx_event_pipe_write_chain_to_temp_file(p);

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe temp offset: %d", p->temp_file->offset);

                if (rc == NGX_AGAIN) {
                    if (ngx_event_flags & NGX_USE_LEVEL_EVENT
                        && p->upstream->read->active
                        && p->upstream->read->ready)
                    {
                        if (ngx_del_event(p->upstream->read, NGX_READ_EVENT, 0)
                                                                  == NGX_ERROR)
                        {
                            return NGX_ABORT;
                        }
                    }
                }

                if (rc != NGX_OK) {
                    return rc;
                }

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else {

                /* if there're no bufs to read in then disable a level event */

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "no pipe bufs to read in");
    
                break;
            }

            n = ngx_recv_chain(p->upstream, chain);

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe recv chain: %d", n);

            if (p->free_raw_bufs) {
                chain->next = p->free_raw_bufs;
            }
            p->free_raw_bufs = chain;

            if (n == NGX_ERROR) {
                p->upstream_error = 1;
                return NGX_ERROR;
            }

            if (n == NGX_AGAIN) {
                if (p->single_buf) {
                    ngx_event_pipe_remove_shadow_links(chain->buf);
                }

                break;
            }

            p->read = 1;

            if (n == 0) {
                p->upstream_eof = 1;
                break;
            }
        }

        p->read_length += n;
        cl = chain;

        while (cl && n > 0) {

            ngx_event_pipe_remove_shadow_links(cl->buf);

            size = cl->buf->end - cl->buf->last;

            if (n >= size) {
                cl->buf->last = cl->buf->end;

                /* STUB */ cl->buf->num = p->num++;

                if (p->input_filter(p, cl->buf) == NGX_ERROR) {
                    return NGX_ABORT;
                }

                n -= size;
                cl = cl->next;

            } else {
                cl->buf->last += n;
                n = 0;
            }
        }

        p->free_raw_bufs = cl;
    }

#if (NGX_DEBUG)

    if (p->in || p->busy || p->free_raw_bufs) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0, "pipe buf");
    }

    for (cl = p->in; cl; cl = cl->next) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in " PTR_FMT ", pos " PTR_FMT ", size: %d",
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos);
    }

    for (cl = p->busy; cl; cl = cl->next) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy " PTR_FMT ", pos " PTR_FMT ", size: %d",
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos);
    }

    for (cl = p->free_raw_bufs; cl; cl = cl->next) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf free " PTR_FMT ", last " PTR_FMT ", size: %d",
                       cl->buf->start, cl->buf->last,
                       cl->buf->end - cl->buf->last);
    }

#endif

    if ((p->upstream_eof || p->upstream_error) && p->free_raw_bufs) {

        /* STUB */ p->free_raw_bufs->buf->num = p->num++;

        if (p->input_filter(p, p->free_raw_bufs->buf) == NGX_ERROR) {
            return NGX_ABORT;
        }

        p->free_raw_bufs = p->free_raw_bufs->next;

        if (p->free_bufs) {
            for (cl = p->free_raw_bufs; cl; cl = cl->next) {
                ngx_pfree(p->pool, cl->buf->start); 
            }
        }
    }

    if (p->cachable && p->in) {
        if (ngx_event_pipe_write_chain_to_temp_file(p) == NGX_ABORT) {
            return NGX_ABORT;
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
{
    size_t        bsize;
    ngx_uint_t    flush;
    ngx_buf_t    *b;
    ngx_chain_t  *out, **ll, *cl, *tl;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", p->downstream->write->ready);

    for ( ;; ) {
        if (p->downstream_error) {
            return ngx_event_pipe_drain_chains(p);
        }

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {

            /* pass the p->out and p->in chains to the output filter */

            if (p->out) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");

                if (p->output_filter(p->output_ctx, p->out) == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }

                p->out = NULL;
            }

            if (p->in) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                if (p->output_filter(p->output_ctx, p->in) == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }

                p->in = NULL;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */

            p->downstream_done = 1;
            break;
        }

        if (!p->downstream->write->ready) {
            break;
        }

        /* bsize is the size of the busy bufs */

        bsize = 0;

        for (cl = p->busy; cl; cl = cl->next) {
            bsize += cl->buf->end - cl->buf->start;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: " SIZE_T_FMT, bsize);

        out = NULL;
        ll = NULL;
        flush = 0;

        for ( ;; ) {
            if (p->out) {
                cl = p->out;

                if (bsize + ngx_buf_size(cl->buf) > p->busy_size) {
                    flush = 1;
                    break;
                }

                p->out = p->out->next;
                ngx_event_pipe_free_shadow_raw_buf(&p->free_raw_bufs,
                                                   cl->buf);

            } else if (!p->cachable && p->in) {
                cl = p->in;

                if (bsize + ngx_buf_size(cl->buf) > p->busy_size) {
                    flush = 1;
                    break;
                }

                p->in = p->in->next;

            } else {
                break;
            }

            bsize += ngx_buf_size(cl->buf);
            cl->next = NULL;
            ngx_chain_add_link(out, ll, cl);
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:" PTR_FMT ", f:%d", out, flush);

        if (out == NULL && !flush) {
            break;
        }

        if (p->output_filter(p->output_ctx, out) == NGX_ERROR) {
            p->downstream_error = 1;
            return ngx_event_pipe_drain_chains(p);
        }

        ngx_chain_update_chains(&p->free, &p->busy, &out, p->tag);

        for (cl = p->free; cl; cl = cl->next) {

            if (cl->buf->temp_file) {
                if (p->cachable || !p->cyclic_temp_file) {
                    continue;
                }

                /* reset p->temp_offset if all bufs had been sent */

                if (cl->buf->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }

            /* TODO: free buf if p->free_bufs && upstream done */

            /* add the free shadow raw buf to p->free_raw_bufs */

            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last = b->start;
                b->shadow = NULL;
                ngx_alloc_link_and_set_buf(tl, b, p->pool, NGX_ABORT);
                ngx_event_pipe_add_free_buf(&p->free_raw_bufs, tl);

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
{
    ssize_t       size, bsize;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *tl, *next, *out, **ll, **last_free, fl;

    if (p->buf_to_file) {
        fl.buf = p->buf_to_file;
        fl.next = p->in;
        out = &fl;

    } else {
        out = p->in;
    }

    if (!p->cachable) {

        size = 0;
        cl = out;
        ll = NULL;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %d", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf " PTR_FMT ", pos " PTR_FMT ", size: %d",
                           cl->buf->start, cl->buf->pos, bsize);

            if ((size + bsize > p->temp_file_write_size)
               || (p->temp_file->offset + size + bsize > p->max_temp_file_size))
            {
                break;
            }

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "size: %d", size);

        if (cl) {
           p->in = cl;
           *ll = NULL;

        } else {
           p->in = NULL;
           p->last_in = &p->in;
        }

    } else {
        p->in = NULL;
        p->last_in = &p->in;
    }

    if (ngx_write_chain_to_temp_file(p->temp_file, out) == NGX_ERROR) {
        return NGX_ABORT;
    }

    for (last_free = &p->free_raw_bufs;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        out = out->next;
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;
        cl->next = NULL;

        b = cl->buf;
        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += b->last - b->pos;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        ngx_chain_add_link(p->out, p->last_out, cl);

        if (b->last_shadow) {
            b->shadow->last = b->shadow->pos = b->shadow->start;
            ngx_alloc_link_and_set_buf(tl, b->shadow, p->pool, NGX_ABORT);
            *last_free = tl;
            last_free = &tl->next;
        }
    }

    return NGX_OK;
}


/* the copy input filter */

ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->free) {
        b = p->free->buf;
        p->free = p->free->next;

    } else {
        if (!(b = ngx_alloc_buf(p->pool))) {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    ngx_alloc_link_and_set_buf(cl, b, p->pool, NGX_ERROR);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "buf #%d", b->num);

    ngx_chain_add_link(p->in, p->last_in, cl);

    return NGX_OK;
}


ngx_inline static void ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf)
{
    ngx_buf_t  *b, *next;

    if (buf->shadow == NULL) {
        return;
    }

    b = buf->shadow;

    while (!b->last_shadow) {
        next = b->shadow;

        b->in_file = 0;
        b->temp_file = 0;
        b->flush = 0;
        b->zerocopy_busy = 0;

        b->shadow = NULL;
        b = next;
    }

    b->in_file = 0;
    b->temp_file = 0;
    b->flush = 0;
    b->zerocopy_busy = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


ngx_inline static void ngx_event_pipe_free_shadow_raw_buf(ngx_chain_t **free,
                                                          ngx_buf_t *buf)
{
    ngx_buf_t    *s;
    ngx_chain_t  *cl, **ll;

    if (buf->shadow == NULL) {
        return;
    }

    for (s = buf->shadow; !s->last_shadow; s = s->shadow) { /* void */ }

    ll = free;

    for (cl = *free ; cl; cl = cl->next) {
        if (cl->buf == s) {
            *ll = cl->next;
            break;
        }

        if (cl->buf->shadow) {
            break;
        }

        ll = &cl->next;
    }
}


ngx_inline static void ngx_event_pipe_add_free_buf(ngx_chain_t **chain,
                                                   ngx_chain_t *cl)
{
    if (*chain == NULL) {
        *chain = cl;
        return;
    }

    if ((*chain)->buf->pos != (*chain)->buf->last) {
        cl->next = (*chain)->next;
        (*chain)->next = cl;

    } else {
        cl->next = (*chain);
        (*chain) = cl;
    }
}


static ngx_int_t ngx_event_pipe_drain_chains(ngx_event_pipe_t *p)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *tl;

    for ( ;; ) {
        if (p->busy) {
            cl = p->busy;
            p->busy = NULL;

        } else if (p->out) {
            cl = p->out;
            p->out = NULL;

        } else if (p->in) {
            cl = p->in;
            p->in = NULL;

        } else {
            return NGX_OK;
        }

        while (cl) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last = b->start;
                b->shadow = NULL;
                ngx_alloc_link_and_set_buf(tl, b, p->pool, NGX_ABORT);
                ngx_event_pipe_add_free_buf(&p->free_raw_bufs, tl);

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
            tl = cl->next;
            cl->next = p->free;
            p->free = cl;
            cl = tl;
        }
    }
}
