
#include <ngx_event_proxy.h>


int ngx_event_proxy_read_upstream(ngx_event_proxy_t *p)
{
    int           n, rc, size;
    ngx_hunk_t   *h, *nh;
    ngx_chain_t  *chain, *temp, *entry, *next;

    p->level++;

ngx_log_debug(p->log, "read upstream");

    for ( ;; ) {

        /* use the free hunks if they exist */

        if (p->free_hunks) {
            chain = p->free_hunks;
            p->free_hunks = NULL;

ngx_log_debug(p->log, "free hunk: %08X:%d" _ chain->hunk _
              chain->hunk->end - chain->hunk->last);

        /* allocate a new hunk if it's still allowed */

        } else if (p->allocated < p->max_block_size) {
            ngx_test_null(h,
                          ngx_create_temp_hunk(p->pool, p->block_size, 20, 20),
                          NGX_ERROR);

            p->allocated += p->block_size;

            ngx_test_null(temp, ngx_alloc_chain_entry(p->pool), NGX_ERROR);
            temp->hunk = h;
            temp->next = NULL;
            chain = temp;

ngx_log_debug(p->log, "new hunk: %08X" _ chain->hunk);

        /* use the shadow hunks if they exist */

        } else if (p->shadow_hunks) {
            chain = p->shadow_hunks;
            p->shadow_hunks = NULL;

ngx_log_debug(p->log, "shadow hunk: %08X" _ chain->hunk);

        /* if it's allowed then save the incoming hunks to a temporary file,
           move the saved hunks to a shadow chain,
           and add the file hunks to an outgoing chain */

        } else if (p->temp_offset < p->max_temp_size) {
            rc = ngx_event_proxy_write_chain_to_temp_file(p);

ngx_log_debug(p->log, "temp offset: %d" _ p->temp_offset);

            if (rc != NGX_OK) {
                return rc;
            }

            chain = p->shadow_hunks;
            p->shadow_hunks = NULL;

ngx_log_debug(p->log, "new shadow hunk: %08X" _ chain->hunk);

        /* if there're no hunks to read in then disable a level event */

        } else {
            if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
                p->block_upstream = 1;
            }

            break;
        }

        n = ngx_recv_chain(p->upstream, chain);

ngx_log_debug(p->log, "recv_chain: %d" _ n);

        if (n == NGX_ERROR) {
            p->upstream_error = 1;
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN) {
            if (p->upstream->read->blocked) {
                if (ngx_add_event(p->upstream->read, NGX_READ_EVENT,
                                               NGX_LEVEL_EVENT) == NGX_ERROR) {
                    return NGX_ERROR;
                }
                p->upstream->read->blocked = 0;
            }

            return NGX_AGAIN;
        }

        if (n == 0) {
            p->free_hunks = chain;
            p->upstream_eof = 1;
            p->block_upstream = 0;
            break;
        }

        /* move the full hunks to a read chain
           and the partial filled hunk to a free chain
           and remove the shadow links for these hunks */

        for (entry = chain; entry && n > 0; entry = next) {
            next = entry->next;
            entry->next = NULL;

            if (entry->hunk->shadow) {
                for (h = entry->hunk->shadow;
                     (h->type & NGX_HUNK_LAST_SHADOW) == 0;
                     h = nh)
                {
                    nh = h->shadow;
                    h->shadow = NULL;
                    h->type &= ~(NGX_HUNK_TEMP
                                 |NGX_HUNK_IN_MEMORY
                                 |NGX_HUNK_RECYCLED);
                }

                h->shadow = NULL;
                h->type &= ~(NGX_HUNK_TEMP
                             |NGX_HUNK_IN_MEMORY
                             |NGX_HUNK_RECYCLED
                             |NGX_HUNK_LAST_SHADOW);
                entry->hunk->shadow = NULL;
            }

            size = entry->hunk->end - entry->hunk->last;

            if (n >= size) {
                entry->hunk->last = entry->hunk->end;

                if (p->read_hunks) {
                    p->last_read_hunk->next = entry;

                } else {
                    p->read_hunks = entry;
                }

                p->last_read_hunk = entry;

                n -= size;

                /* the copy input filter */

                if (p->input_filter == NULL) {
                    ngx_test_null(h, ngx_alloc_hunk(p->pool), NGX_ERROR);
                    ngx_memcpy(h, entry->hunk, sizeof(ngx_hunk_t));
                    h->shadow = entry->hunk;
                    h->type |= NGX_HUNK_LAST_SHADOW;

                    ngx_test_null(temp, ngx_alloc_chain_entry(p->pool),
                                  NGX_ERROR);
                    temp->hunk = h;
                    temp->next = NULL;

                    if (p->in_hunks) {
                        p->last_in_hunk->next = temp;

                    } else {
                        p->in_hunks = temp;
                    }

                    p->last_in_hunk = temp;
                }

            } else {
                entry->hunk->last += n;
                p->free_hunks = entry;

                n = 0;
            }
        }

ngx_log_debug(p->log, "rest chain: %08X" _ entry);

        /* if the rest hunks are shadow then move them to a shadow chain
           otherwise add them to a free chain */

        if (entry) {
            if (entry->hunk->shadow) {
                p->shadow_hunks = entry;

            } else {
                if (p->free_hunks) {
                    p->free_hunks->next = entry;

                } else {
                    p->free_hunks = entry;
                }
            }

            p->block_upstream = 0;
            break;
        }

        /* the input filter i.e. that moves HTTP/1.1 chunks
           from a read chain to an incoming chain */

        if (p->input_filter) {
            if (p->input_filter(p) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
    }

ngx_log_debug(p->log, "eof: %d block: %d" _
              p->upstream_eof _ p->block_upstream);

    /* if there's the end of upstream response then move
       the partially filled hunk from a free chain to an incoming chain */

    if (p->upstream_eof) {
        p->upstream->read->ready = 0;

        if (p->free_hunks
            && p->free_hunks->hunk->pos < p->free_hunks->hunk->last)
        {
            if (p->input_filter) {
                if (p->input_filter(p) == NGX_ERROR) {
                    return NGX_ERROR;
                }

            } else {
                entry = p->free_hunks;

                if (p->in_hunks) {
                    p->last_in_hunk->next = entry;

                } else {
                    p->in_hunks = entry;
                }

                p->last_in_hunk = entry;
            }

            p->free_hunks = entry->next;
            entry->next = NULL;
        }

#if 0
        /* free the unneeded hunks */

        for (entry = p->free_hunks; entry; entry = ce->next) {
            ngx_free_hunk(p->pool, entry->hunk);
        }
#endif

        if (p->in_hunks) {
            p->last_in_hunk->hunk->type |= NGX_HUNK_LAST;

        } else if (p->out_hunks) {
            p->last_out_hunk->hunk->type |= NGX_HUNK_LAST;
        }
    }

    if (p->cachable) {
        if (p->in_hunks) {
            rc = ngx_event_proxy_write_chain_to_temp_file(p);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        if (p->out_hunks && p->client->write->ready) {
            rc = ngx_event_proxy_write_to_client(p);
        }

    } else if ((p->out_hunks || p->in_hunks) && p->client->write->ready) {
        rc = ngx_event_proxy_write_to_client(p);
    }

    p->level--;

ngx_log_debug(p->log, "level: %d" _ p->level);

    if (p->level == 0 && p->block_upstream) {
        p->upstream->read->blocked = 1;
        if (ngx_del_event(p->upstream->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (p->upstream_eof) {
        return NGX_OK;
    } else {
        return NGX_AGAIN;
    }
}


int ngx_event_proxy_write_to_client(ngx_event_proxy_t *p)
{
    int           rc;
    ngx_hunk_t   *h;
    ngx_chain_t  *entry;

ngx_log_debug(p->log, "write to client");

    h = p->busy_hunk;

    for ( ;; ) {

        if (h == NULL) {
            if (p->out_hunks) {
                entry = p->out_hunks;
                p->out_hunks = entry->next;
                h = entry->hunk;

                if (p->shadow_hunks) {
                    if (p->shadow_hunks->hunk == h->shadow) {
                        p->shadow_hunks = p->shadow_hunks->next;
                    }
                }

                entry->next = NULL;

            } else if (p->cachable == 0 && p->in_hunks) {
                entry = p->in_hunks;
                p->in_hunks = entry->next;
                h = entry->hunk;
                entry->next = NULL;
            }

ngx_log_debug(p->log, "event proxy write hunk: %08X:%08X" _ h _ h->pos);

            if (h == NULL) {
                if (p->upstream->read->ready) {
                    rc = ngx_event_proxy_read_upstream(p);
                }

                return NGX_OK;
            }
        }

ngx_log_debug(p->log, "event proxy write: %d" _ h->last - h->pos);

        rc = p->output_filter(p->output_data, h);

ngx_log_debug(p->log, "event proxy: %d" _ rc);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_AGAIN
            || (h->type & NGX_HUNK_IN_MEMORY && h->pos < h->last)
            || (h->type & NGX_HUNK_FILE && h->file_pos < h->file_last))
        {
            if (p->busy_hunk == NULL) {
                p->busy_hunk = h;
            }
            return NGX_AGAIN;
        }

        p->busy_hunk = NULL;

        /* if the complete hunk is the file hunk and it has a shadow hunk
           then add a shadow hunk to a free chain */

        if (h->type & NGX_HUNK_FILE) {
            if (p->cachable == 0 && p->out_hunks == NULL) {
                p->temp_offset = 0;
            }
        }

        if ((h->type & NGX_HUNK_LAST_SHADOW) == 0) {
            h = NULL;
            continue;
        }


        h->shadow->shadow = NULL;
        h = h->shadow;

#if 0
        /* free the unneeded hunk */

        if (p->upstream_eof) {
            ngx_free_hunk(p->pool, h);
            continue;
        }
#endif

        h->pos = h->last = h->start;

        entry->hunk = h;

        /* if the first hunk in a free chain is partially filled
           then add the complete hunk after the first free hunk */

        if (p->free_hunks
            && p->free_hunks->hunk->start != p->free_hunks->hunk->last)
        {
            entry->next = p->free_hunks->next;
            p->free_hunks->next = entry;

        } else {
            entry->next = p->free_hunks;
            p->free_hunks = entry;
        }

        h = NULL;
    }
}


int ngx_event_proxy_write_chain_to_temp_file(ngx_event_proxy_t *p)
{
    int           i, rc, size;
    ngx_hunk_t   *h;
    ngx_chain_t  *entry, *next, *saved_in, *saved_read;

ngx_log_debug(p->log, "write to file");

    if (p->temp_file->fd == NGX_INVALID_FILE) {
        rc = ngx_create_temp_file(p->temp_file, p->temp_path, p->pool,
                                  p->number, p->random, p->cachable);

        if (rc != NGX_OK) {
            return rc;
        }

        if (p->cachable == 0 && p->temp_file_warn) {
            ngx_log_error(NGX_LOG_WARN, p->log, 0, p->temp_file_warn);
        }
    }

    if (p->cachable == 0) {

        entry = p->read_hunks;
        size = 0;

        do {
            size += entry->hunk->last - entry->hunk->pos;
            if (size >= p->file_block_size) {
                break;
            }
            entry = entry->next;

        } while (entry);

        saved_read = entry->next;
        entry->next = NULL;

        if (saved_read) {
            for (entry = p->in_hunks; entry->next; entry = entry->next) {
                if (entry->next->hunk->shadow == saved_read->hunk) {
                    break;
                }
            }
            saved_in = entry->next;
            entry->next = NULL;

        } else {
            saved_in = NULL;
        }

    } else {
        saved_read = NULL;
        saved_in = NULL;
    }

    if (ngx_write_chain_to_file(p->temp_file, p->in_hunks, p->temp_offset,
                                p->pool) == NGX_ERROR) {
        return NGX_ERROR;
    }

    for (entry = p->in_hunks; entry; entry = next) {
        next = entry->next;
        entry->next = NULL;

        h = entry->hunk;
        h->type |= NGX_HUNK_FILE;
        h->file = p->temp_file;
        h->file_pos = p->temp_offset;
        p->temp_offset += h->last - h->pos;
        h->file_last = p->temp_offset;

ngx_log_debug(p->log, "event proxy file hunk: %08X:%08X" _ h _ h->pos);

        if (entry->hunk->type & NGX_HUNK_LAST_SHADOW) {
            entry->hunk->shadow->last = entry->hunk->shadow->pos;
        }

        if (p->out_hunks) {
            p->last_out_hunk->next = entry;

        } else {
            p->out_hunks = entry;
        }

        p->last_out_hunk = entry;
    }

    p->shadow_hunks = p->read_hunks;

    p->read_hunks = saved_read;
    p->in_hunks = saved_in;

    return NGX_OK;
}
