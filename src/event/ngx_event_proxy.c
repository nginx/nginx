
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_proxy.h>

static int ngx_event_proxy_write_chain_to_temp_file(ngx_event_proxy_t *p);
ngx_inline static void ngx_remove_shadow_links(ngx_hunk_t *hunk);
ngx_inline static void ngx_remove_shadow_free_raw_hunk(ngx_chain_t **free,
                                                       ngx_hunk_t *h);
ngx_inline static void ngx_add_after_partially_filled_hunk(ngx_chain_t **chain,
                                                           ngx_chain_t *ce);


int ngx_event_proxy_read_upstream(ngx_event_proxy_t *p)
{
    int           n, rc, size;
    ngx_hunk_t   *h;
    ngx_chain_t  *chain, *ce, *te;

    p->upstream_level++;

    ngx_log_debug(p->log, "read upstream: %d" _ p->upstream->read->ready);

    while (p->preread_hunks
           || (p->upstream->read->ready && !p->upstream_done))
    {
        if (p->preread_hunks) {

            /* use the pre-read hunks if they exist */

            chain = p->preread_hunks;
            p->preread_hunks = NULL;
            n = p->preread_size;

            ngx_log_debug(p->log, "preread: %d" _ n);

        } else {

#if (HAVE_KQUEUE)

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a hunk on these conditions
             * and not to call ngx_recv_chain().
             */

            if (ngx_event_flags == NGX_HAVE_KQUEUE_EVENT) {

                if (p->upstream->read->error) {
                    ngx_log_error(NGX_LOG_ERR, p->log, p->upstream->read->error,
                                  "readv() failed");
                    p->upstream_error = 1;

                    break;

                } else if (p->upstream->read->eof
                           && p->upstream->read->available == 0) {
                    p->upstream_eof = 1;

                    break;
                }
            }
#endif

            if (p->free_raw_hunks) {

                /* use the free hunks if they exist */

                chain = p->free_raw_hunks;
                p->free_raw_hunks = NULL;

            } else if (p->hunks < p->bufs.num) {

                /* allocate a new hunk if it's still allowed */

                ngx_test_null(h, ngx_create_temp_hunk(p->pool,
                                                      p->bufs.size, 0, 0),
                              NGX_ABORT);
                p->hunks++;

                ngx_alloc_ce_and_set_hunk(te, h, p->pool, NGX_ABORT);
                chain = te;

            } else if (!p->cachable && p->downstream->write->ready) {

                /*
                 * If the hunks are not needed to be saved in a cache and
                 * a downstream is ready then write the hunks to a downstream.
                 */

                ngx_log_debug(p->log, "downstream ready");

                break;

            } else if (p->temp_offset < p->max_temp_file_size) {

                /*
                 * If it's allowed then save some hunks from r->in
                 * to a temporary file, and add them to a r->out chain.
                 */

                rc = ngx_event_proxy_write_chain_to_temp_file(p);

                ngx_log_debug(p->log, "temp offset: %d" _ p->temp_offset);

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
                p->free_raw_hunks = NULL;

            } else {

                /* if there're no hunks to read in then disable a level event */

                ngx_log_debug(p->log, "no hunks to read in");
    
                break;
            }

            n = ngx_recv_chain(p->upstream, chain);

            ngx_log_debug(p->log, "recv_chain: %d" _ n);

            if (n == NGX_ERROR) {
                p->upstream_error = 1;
                return NGX_ERROR;
            }

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                p->free_raw_hunks = chain;
                p->upstream_eof = 1;

                break;
            }

        }

        for (ce = chain; ce && n > 0; ce = ce->next) {

            ngx_remove_shadow_links(ce->hunk);

            size = ce->hunk->end - ce->hunk->last;

            if (n >= size) {
                ce->hunk->last = ce->hunk->end;

                if (p->input_filter(p, ce->hunk) == NGX_ERROR) {
                    return NGX_ABORT;
                }

                n -= size;

                chain = ce->next;

            } else {
                ce->hunk->last += n;
                n = 0;
            }
        }

        p->free_raw_hunks = chain;
    }

    if ((p->upstream_eof || p->upstream_error) && p->free_raw_hunks) {
        if (p->input_filter(p, p->free_raw_hunks->hunk) == NGX_ERROR) {
            return NGX_ABORT;
        }

        /* TODO: p->free_raw_hunk->next can be free()ed */
        p->free_raw_hunks = p->free_raw_hunks->next;
    }

    if (p->cachable) {
        if (p->in) {
            rc = ngx_event_proxy_write_chain_to_temp_file(p);

            if (rc != NGX_OK) {
                return rc;
            }
        }

        if (p->out && p->downstream->write->ready) {
            if (ngx_event_proxy_write_to_downstream(p) == NGX_ABORT) {
                return NGX_ABORT;
            }
        }

    } else if ((p->out || p->in) && p->downstream->write->ready) {
        if (ngx_event_proxy_write_to_downstream(p) == NGX_ABORT) {
            return NGX_ABORT;
        }
    }

    p->upstream_level--;

ngx_log_debug(p->log, "upstream level: %d" _ p->upstream_level);

    if (p->upstream_level == 0) {
        if (ngx_handle_read_event(p->upstream->read) == NGX_ERROR) {
            return NGX_ABORT;
        }
    }

    return NGX_OK;
}


int ngx_event_proxy_write_to_downstream(ngx_event_proxy_t *p)
{
    int           rc;
    ngx_hunk_t   *h;
    ngx_chain_t  *out, *ce, *te;

    while (p->downstream->write->ready) {

        if (p->out) {
            out = p->out;

            if (p->busy_len + ngx_hunk_size(out->hunk) > p->max_busy_len) {
                break;
            }

            p->out = p->out->next;
            ngx_remove_shadow_free_raw_hunk(&p->free_raw_hunks, out->hunk);

        } else if (!p->cachable && p->in) {
            out = p->in;

            if (p->busy_len + ngx_hunk_size(out->hunk) > p->max_busy_len) {
                break;
            }

            p->in = p->in->next;

        } else {
            break;
        }

        out->next = NULL;

        rc = p->output_filter(p->output_ctx, out->hunk);

        ngx_chain_update_chains(&p->free, &p->busy, &out);

        /* calculate p->busy_len */

        p->busy_len = 0;
        for (ce = p->busy; ce; ce = ce->next) {
            p->busy_len += ngx_hunk_size(ce->hunk);
        }

        /* add the free shadow raw hunks to p->free_raw_hunks */

        for (ce = p->free; ce; ce = ce->next) {
            if (ce->hunk->type & NGX_HUNK_LAST_SHADOW) {
                h = ce->hunk->shadow;
                /* THINK NEEDED ??? */ h->pos = h->last = h->start;
                h->shadow = NULL;
                ngx_alloc_ce_and_set_hunk(te, ce->hunk->shadow, p->pool,
                                          NGX_ABORT);
                ngx_add_after_partially_filled_hunk(&p->free_raw_hunks, te);

                ce->hunk->type &= ~NGX_HUNK_LAST_SHADOW;
            }
            ce->hunk->shadow = NULL;
        }

        if (p->upstream->read->ready) {
            if (ngx_event_proxy_read_upstream(p) == NGX_ERROR) {
                return NGX_ABORT;
            }
        }
    }

    if (p->downstream_level == 0) {
        if (ngx_handle_write_event(p->downstream->write,
                                           /* TODO: lowat */ 0) == NGX_ERROR) {
            return NGX_ABORT;
        }
    }

    if (p->upstream_done && p->in == NULL && p->out == NULL) {
        p->downstream_done = 1;
    }

    return NGX_OK;
}


static int ngx_event_proxy_write_chain_to_temp_file(ngx_event_proxy_t *p)
{
    int           rc, size;
    ngx_hunk_t   *h;
    ngx_chain_t  *ce, *next, *in, **last;

    ngx_log_debug(p->log, "write to file");

    if (p->temp_file->fd == NGX_INVALID_FILE) {
        rc = ngx_create_temp_file(p->temp_file, p->temp_path, p->pool,
                                  p->cachable);

        if (rc == NGX_ERROR) {
            return NGX_ABORT;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (!p->cachable && p->temp_file_warn) {
            ngx_log_error(NGX_LOG_WARN, p->log, 0, p->temp_file_warn);
        }
    }

    if (!p->cachable) {

        size = 0;
        ce = p->in;

        do {
            size += ce->hunk->last - ce->hunk->pos;
            if (size >= p->temp_file_write_size) {
                break;
            }
            ce = ce->next;

        } while (ce);

        in = ce->next;
        last = &ce->next;
        ce->next = NULL;

    } else {
        in = NULL;
        last = &p->in;
    }

    if (ngx_write_chain_to_file(p->temp_file, p->in, p->temp_offset,
                                p->pool) == NGX_ERROR) {
        return NGX_ABORT;
    }

    for (ce = p->in; ce; ce = next) {
        next = ce->next;
        ce->next = NULL;

        h = ce->hunk;
        h->type |= NGX_HUNK_FILE;
        h->file = p->temp_file;
        h->file_pos = p->temp_offset;
        p->temp_offset += h->last - h->pos;
        h->file_last = p->temp_offset;

        if (h->type & NGX_HUNK_LAST_SHADOW) {
            h->shadow->last = h->shadow->pos = h->shadow->start;
        }

        ngx_chain_add_ce(p->out, p->last_out, ce);
    }

    p->in = in;
    p->last_in = last;

    return NGX_OK;
}


/* the copy input filter */

int ngx_event_proxy_copy_input_filter(ngx_event_proxy_t *p, ngx_hunk_t *hunk)
{
    ngx_hunk_t   *h;
    ngx_chain_t  *ce;

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
    h->type |= NGX_HUNK_LAST_SHADOW|NGX_HUNK_RECYCLED;
    hunk->shadow = h;

    ngx_alloc_ce_and_set_hunk(ce, h, p->pool, NGX_ERROR);
    ngx_chain_add_ce(p->in, p->last_in, ce);

    return NGX_OK;
}


ngx_inline static void ngx_remove_shadow_links(ngx_hunk_t *hunk)
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


ngx_inline static void ngx_remove_shadow_free_raw_hunk(ngx_chain_t **free,
                                                       ngx_hunk_t *h)
{
    ngx_hunk_t   *s;
    ngx_chain_t  *ce, **le;

    if (h->shadow == NULL) {
        return;
    }

    for (s = h->shadow; !(s->type & NGX_HUNK_LAST_SHADOW); s = s->shadow) {
        /* void */
    }

    le = free;

    for (ce = *free ; ce; ce = ce->next) {
        if (ce->hunk == s) {
            *le = ce->next;
            break;
        }

        if (ce->hunk->shadow) {
            break;
        }

        le = &ce->next;
    }
}


ngx_inline static void ngx_add_after_partially_filled_hunk(ngx_chain_t **chain,
                                                           ngx_chain_t *ce)
{
    if (*chain == NULL) {
        *chain = ce;
        return;
    }

    if ((*chain)->hunk->pos != (*chain)->hunk->last) {
        ce->next = (*chain)->next;
        (*chain)->next = ce;

    } else {
        ce->next = (*chain);
        (*chain) = ce;
    }
}
