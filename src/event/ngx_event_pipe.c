
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe.h>


static int ngx_event_pipe_read_upstream(ngx_event_pipe_t *p);
static int ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p);

static int ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p);
ngx_inline static void ngx_event_pipe_remove_shadow_links(ngx_hunk_t *hunk);
ngx_inline static void ngx_event_pipe_free_shadow_raw_hunk(ngx_chain_t **free,
                                                           ngx_hunk_t *h);
ngx_inline static void ngx_event_pipe_add_free_hunk(ngx_chain_t **chain,
                                                    ngx_chain_t *cl);
static int ngx_event_pipe_drain_chains(ngx_event_pipe_t *p);


int ngx_event_pipe(ngx_event_pipe_t *p, int do_write)
{
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

        if (ngx_handle_read_event(rev, (rev->eof || rev->error)) == NGX_ERROR) {
            return NGX_ABORT;
        }

        if (rev->active) {
            ngx_add_timer(rev, p->read_timeout);
        }
    }

    if (p->downstream->fd != -1) {
        wev = p->downstream->write;

        if (ngx_handle_write_event(wev, p->send_lowat) == NGX_ERROR) {
            return NGX_ABORT;
        }

        if (wev->active) {
            ngx_add_timer(wev, p->send_timeout);
        }
    }

    return NGX_OK;
}


int ngx_event_pipe_read_upstream(ngx_event_pipe_t *p)
{
    int           n, rc, size;
    ngx_hunk_t   *h;
    ngx_chain_t  *chain, *cl, *tl;

    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return NGX_OK;
    }

    ngx_log_debug(p->log, "read upstream: %d" _ p->upstream->read->ready);

    for ( ;; ) {

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {
            break;
        }

        if (p->preread_hunks == NULL && !p->upstream->read->ready) {
            break;
        }

        if (p->preread_hunks) {

            /* use the pre-read hunks if they exist */

            p->read = 1;
            chain = p->preread_hunks;
            p->preread_hunks = NULL;
            n = p->preread_size;

            ngx_log_debug(p->log, "preread: %d" _ n);

        } else {

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a hunk on these conditions
             * and not to call ngx_recv_chain().
             */

            if (p->upstream->read->available == 0
                && (p->upstream->read->kq_eof || p->upstream->read->aio_eof))
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

            if (p->free_raw_hunks) {

                /* use the free hunks if they exist */

                chain = p->free_raw_hunks;
                if (p->single_buf) {
                    p->free_raw_hunks = p->free_raw_hunks->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_hunks = NULL;
                }

            } else if (p->hunks < p->bufs.num) {

                /* allocate a new hunk if it's still allowed */

                ngx_test_null(h, ngx_create_temp_hunk(p->pool, p->bufs.size),
                              NGX_ABORT);
                p->hunks++;

                ngx_alloc_link_and_set_hunk(tl, h, p->pool, NGX_ABORT);
                chain = tl;

            } else if (!p->cachable && p->downstream->write->ready) {

                /*
                 * if the hunks are not needed to be saved in a cache and
                 * a downstream is ready then write the hunks to a downstream
                 */

                p->upstream_blocked = 1;

                ngx_log_debug(p->log, "downstream ready");

                break;

            } else if (p->cachable
                       || p->temp_file->offset < p->max_temp_file_size)
            {

                /*
                 * if it's allowed then save some hunks from r->in
                 * to a temporary file, and add them to a r->out chain
                 */

                rc = ngx_event_pipe_write_chain_to_temp_file(p);

                ngx_log_debug(p->log, "temp offset: %d" _ p->temp_file->offset);

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

                chain = p->free_raw_hunks;
                if (p->single_buf) {
                    p->free_raw_hunks = p->free_raw_hunks->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_hunks = NULL;
                }

            } else {

                /* if there're no hunks to read in then disable a level event */

                ngx_log_debug(p->log, "no hunks to read in");
    
                break;
            }

            n = ngx_recv_chain(p->upstream, chain);

            ngx_log_debug(p->log, "recv_chain: %d" _ n);

            if (p->free_raw_hunks) {
                chain->next = p->free_raw_hunks;
            }
            p->free_raw_hunks = chain;

            if (n == NGX_ERROR) {
                p->upstream_error = 1;
                return NGX_ERROR;
            }

            if (n == NGX_AGAIN) {
                if (p->single_buf) {
                    ngx_event_pipe_remove_shadow_links(chain->hunk);
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

            ngx_event_pipe_remove_shadow_links(cl->hunk);

            size = cl->hunk->end - cl->hunk->last;

            if (n >= size) {
                cl->hunk->last = cl->hunk->end;

/* STUB */ cl->hunk->num = p->num++;

                if (p->input_filter(p, cl->hunk) == NGX_ERROR) {
                    return NGX_ABORT;
                }

                n -= size;
                cl = cl->next;

            } else {
                cl->hunk->last += n;
                n = 0;
            }
        }

        p->free_raw_hunks = cl;
    }

    if ((p->upstream_eof || p->upstream_error) && p->free_raw_hunks) {
/* STUB */ p->free_raw_hunks->hunk->num = p->num++;
        if (p->input_filter(p, p->free_raw_hunks->hunk) == NGX_ERROR) {
            return NGX_ABORT;
        }

        p->free_raw_hunks = p->free_raw_hunks->next;

        if (p->free_bufs) {
            for (cl = p->free_raw_hunks; cl; cl = cl->next) {
                ngx_pfree(p->pool, cl->hunk->start); 
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


int ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
{
    size_t        bsize, to_write;
    ngx_hunk_t   *h;
    ngx_chain_t  *out, **ll, *cl, *tl;

    ngx_log_debug(p->log, "write downstream: %d" _ p->downstream->write->ready);

    for ( ;; ) {
        if (p->downstream_error) {
            return ngx_event_pipe_drain_chains(p);
        }

        if ((p->upstream_eof || p->upstream_error || p->upstream_done)
            && p->out == NULL && p->in == NULL)
        {
            p->downstream_done = 1;
            break;
        }

        if (!p->downstream->write->ready) {
            break;
        }

        /*
         * bsize is the busy hunks size
         * to_write is the size of data that to be written
         */

        bsize = 0;
        to_write = 0;

        if (!(p->upstream_eof || p->upstream_error || p->upstream_done)) {
            for (cl = p->busy; cl; cl = cl->next) {
                bsize += cl->hunk->end - cl->hunk->start;
                to_write += ngx_hunk_size(cl->hunk);
            }
        }

        out = NULL;
        ll = NULL;

        for ( ;; ) {
            if (p->out) {
                cl = p->out;

                if (!(p->upstream_eof || p->upstream_error || p->upstream_done)
                    && (bsize + ngx_hunk_size(cl->hunk) > p->busy_size))
                {
                    break;
                }

                p->out = p->out->next;
                ngx_event_pipe_free_shadow_raw_hunk(&p->free_raw_hunks,
                                                    cl->hunk);

            } else if (!p->cachable && p->in) {
                cl = p->in;

                if (!(p->upstream_eof || p->upstream_error || p->upstream_done)
                    && (bsize + ngx_hunk_size(cl->hunk) > p->busy_size))
                {
                    break;
                }

                p->in = p->in->next;

            } else {
                break;
            }

            bsize += ngx_hunk_size(cl->hunk);
            cl->next = NULL;
            ngx_chain_add_link(out, ll, cl);
        }

        if (out == NULL) {
            ngx_log_debug(p->log, "no hunks to write BUSY: %d" _ to_write);

            if (!(p->upstream_blocked && to_write)) {
                break;
            }

            /*
             * if the upstream is blocked and there are the busy hunks
             * to write then write these hunks
             */
        }

        if (p->output_filter(p->output_ctx, out) == NGX_ERROR) {
            p->downstream_error = 1;

            /* handle the downstream error at the begin of a cycle */

            continue;
        }

        ngx_chain_update_chains(&p->free, &p->busy, &out, p->tag);

        for (cl = p->free; cl; cl = cl->next) {

            if (cl->hunk->type & NGX_HUNK_TEMP_FILE) {
                if (p->cachable || !p->cyclic_temp_file) {
                    continue;
                }

                /* reset p->temp_offset if all hunks had been sent */

                if (cl->hunk->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }

            /* TODO: free hunk if p->free_bufs && upstream done */

            /* add the free shadow raw hunk to p->free_raw_hunks */

            if (cl->hunk->type & NGX_HUNK_LAST_SHADOW) {
                h = cl->hunk->shadow;
                h->pos = h->last = h->start;
                h->shadow = NULL;
                ngx_alloc_link_and_set_hunk(tl, h, p->pool, NGX_ABORT);
                ngx_event_pipe_add_free_hunk(&p->free_raw_hunks, tl);

                cl->hunk->type &= ~NGX_HUNK_LAST_SHADOW;
            }
            cl->hunk->shadow = NULL;

#if 0
            if (p->cyclic_temp_file && (cl->hunk->type & NGX_HUNK_TEMP_FILE)) {

                /* reset p->temp_offset if all hunks had been sent */

                if (cl->hunk->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }
#endif
        }
    }

    return NGX_OK;
}


static int ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
{
    int           size, hsize;
    char         *save_pos;
    ngx_hunk_t   *h;
    ngx_chain_t  *cl, *tl, *next, *out, **ll, **last_free;

    ngx_log_debug(p->log, "write to file");

    out = p->in;

    if (out->hunk->type & NGX_HUNK_PREREAD) {
        save_pos = out->hunk->pos;
        out->hunk->pos = out->hunk->start;

    } else {
        save_pos = NULL;
    }

    if (!p->cachable) {

        size = 0;
        cl = p->in;
        ll = NULL;

ngx_log_debug(p->log, "offset: %d" _ p->temp_file->offset);

        do {
            hsize = cl->hunk->last - cl->hunk->pos;

ngx_log_debug(p->log, "hunk size: %d" _ hsize);

            if ((size + hsize > p->temp_file_write_size)
               || (p->temp_file->offset + size + hsize > p->max_temp_file_size))
            {
                break;
            }

            size += hsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

ngx_log_debug(p->log, "size: %d" _ size);

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

    for (last_free = &p->free_raw_hunks;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    if (out->hunk->type & NGX_HUNK_PREREAD) {
        p->temp_file->offset += save_pos - out->hunk->pos;
        out->hunk->pos = save_pos;
        out->hunk->type &= ~NGX_HUNK_PREREAD;
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;
        cl->next = NULL;

        h = cl->hunk;
        h->file = &p->temp_file->file;
        h->file_pos = p->temp_file->offset;
        p->temp_file->offset += h->last - h->pos;
        h->file_last = p->temp_file->offset;

        h->type |= NGX_HUNK_FILE|NGX_HUNK_TEMP_FILE;

#if 0
        if (p->cachable) {
            h->type |= NGX_HUNK_FILE;
        } else {
            h->type |= NGX_HUNK_FILE|NGX_HUNK_TEMP_FILE;
        }
#endif

        ngx_chain_add_link(p->out, p->last_out, cl);

        if (h->type & NGX_HUNK_LAST_SHADOW) {
            h->shadow->last = h->shadow->pos = h->shadow->start;
            ngx_alloc_link_and_set_hunk(tl, h->shadow, p->pool, NGX_ABORT);
            *last_free = tl;
            last_free = &tl->next;
        }
    }

    return NGX_OK;
}


/* the copy input filter */

int ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_hunk_t *hunk)
{
    ngx_hunk_t   *h;
    ngx_chain_t  *cl;

ngx_log_debug(p->log, "COPY");

    if (hunk->pos == hunk->last) {
        return NGX_OK;
    }

    if (p->free) {
        h = p->free->hunk;
        p->free = p->free->next;

    } else {
        ngx_test_null(h, ngx_alloc_hunk(p->pool), NGX_ERROR);
    }

    ngx_memcpy(h, hunk, sizeof(ngx_hunk_t));
    h->shadow = hunk;
    h->tag = p->tag;
    h->type |= NGX_HUNK_LAST_SHADOW|NGX_HUNK_RECYCLED;
    hunk->shadow = h;

    ngx_alloc_link_and_set_hunk(cl, h, p->pool, NGX_ERROR);
ngx_log_debug(p->log, "HUNK %d" _ h->num);
    ngx_chain_add_link(p->in, p->last_in, cl);

    return NGX_OK;
}


ngx_inline static void ngx_event_pipe_remove_shadow_links(ngx_hunk_t *hunk)
{
    ngx_hunk_t  *h, *next;

    if (hunk->shadow == NULL) {
        return;
    }

    h = hunk->shadow;

    while (!(h->type & NGX_HUNK_LAST_SHADOW)) {
        next = h->shadow;
        h->type &= ~(NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY|NGX_HUNK_RECYCLED);
        h->shadow = NULL;
        h = next;
    }

    h->type &= ~(NGX_HUNK_TEMP
                 |NGX_HUNK_IN_MEMORY
                 |NGX_HUNK_RECYCLED
                 |NGX_HUNK_LAST_SHADOW);
    h->shadow = NULL;

    hunk->shadow = NULL;
}


ngx_inline static void ngx_event_pipe_free_shadow_raw_hunk(ngx_chain_t **free,
                                                           ngx_hunk_t *h)
{
    ngx_hunk_t   *s;
    ngx_chain_t  *cl, **ll;

    if (h->shadow == NULL) {
        return;
    }

    for (s = h->shadow; !(s->type & NGX_HUNK_LAST_SHADOW); s = s->shadow) {
        /* void */
    }

    ll = free;

    for (cl = *free ; cl; cl = cl->next) {
        if (cl->hunk == s) {
            *ll = cl->next;
            break;
        }

        if (cl->hunk->shadow) {
            break;
        }

        ll = &cl->next;
    }
}


ngx_inline static void ngx_event_pipe_add_free_hunk(ngx_chain_t **chain,
                                                    ngx_chain_t *cl)
{
    if (*chain == NULL) {
        *chain = cl;
        return;
    }

    if ((*chain)->hunk->pos != (*chain)->hunk->last) {
        cl->next = (*chain)->next;
        (*chain)->next = cl;

    } else {
        cl->next = (*chain);
        (*chain) = cl;
    }
}


static int ngx_event_pipe_drain_chains(ngx_event_pipe_t *p)
{
    ngx_hunk_t   *h;
    ngx_chain_t  *cl, *tl;

    for ( ;; ) {
        if (p->busy) {
            cl = p->busy;

        } else if (p->out) {
            cl = p->out;

        } else if (p->in) {
            cl = p->in;

        } else {
            return NGX_OK;
        }

        while (cl) {
            if (cl->hunk->type & NGX_HUNK_LAST_SHADOW) {
                h = cl->hunk->shadow;
                h->pos = h->last = h->start;
                h->shadow = NULL;
                ngx_alloc_link_and_set_hunk(tl, h, p->pool, NGX_ABORT);
                ngx_event_pipe_add_free_hunk(&p->free_raw_hunks, tl);

                cl->hunk->type &= ~NGX_HUNK_LAST_SHADOW;
            }

            cl->hunk->shadow = NULL;
            tl = cl->next;
            cl->next = p->free;
            p->free = cl;
            cl = tl;
        }
    }
}
