



int ngx_http_start_read_client_body(ngx_http_proxy_ctx_t *p)
{
    int                  first_part, size;
    ngx_hunk_t          *h;
    ngx_http_request_t  *r;

    r = p->request;

    first_part = r->header_in->last - r->header_in->pos;

    if (first_part > r->headers_in.content_length_n) {
        first_part = r->headers_in.content_length_n;
        size = 0;

    } else {
        size = r->headers_in.content_length_n - first_part;
        if (size > p->lcf->client_request_buffer_size) {
            size = p->lcf->client_request_buffer_size;

        } else if (size > NGX_PAGE_SIZE) {
            size = ((size + NGX_PAGE_SIZE) / NGX_PAGE_SIZE) * NGX_PAGE_SIZE;
        }

        if (size) {
            ngx_test_null(p->client_request_hunk, ngx_palloc(r->pool, size),
                          NGX_ERROR);
        }
    }

    if (first_part) {
        ngx_test_null(h, ngx_alloc_hunk(r->pool), NGX_ERROR);

        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
        h->pos = h->start = h->pre_start = r->header_in->pos;
        h->last = h->end = h->post_end = r->header_in->pos + first_part;
        h->file_pos = h->file_last = 0;
        h->file = NULL;
        h->shadow = NULL;
        h->tag = 0;

        p->client_first_part_hunk = h;
    }

    return NGX_OK;
}


int ngx_http_read_client_body(ngx_event_t *rev)
{

    do {
        if (r->header_in->last < r->header_in->end) {
            rb->chain[0].hunk = r->header_in;

            if (rb->hunk) {
                rb->chain[0].next = &rb->chain[1];
                rb->chain[1].hunk = rb->hunk;
                rb->chain[1].next = NULL;

            } else {
                rb->chain[0].next = NULL;
            }

        } else {
            rb->chain[0].hunk = rb->hunk;
            rb->chain[0].next = NULL;
        }

        n = ngx_recv_chain(c, &rb->chain);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        for (entry = &rb->chain; entry; entry = entry->next) {
            size = entry->hunk->end - entry->hunk->last;

            if (n >= size) {
                n -= size;
                entry->hunk->last = entry->hunk->end;

                continue;
            }

            entry->hunk->last += n;

            break;
        }

        if (rb->hunk && rb->hunk->last == rb->hunk->end) {
            if (rb->temp_file->fd == NGX_INVALID_FILE) {
                rc = ngx_create_temp_file(rb->temp_file, rb->temp_path, r->pool,
                                          rb->number, rb->random, 0);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    return NGX_AGAIN;
                }
            }

            n = ngx_write_file(rb->temp_file, rb->hunk,
                               rb->hunk->last - rb->hunk->pos, rb->offset);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            rb->offset += n;
            rb->hunk->last = rb->hunk->pos;
        }

    } while (rev->ready);

    return NGX_OK;
}


int ngx_init_client_request_body_chain(ngx_http_reuqest_t *r)
{
    int                       i;
    ngx_hunk_t               *h;
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    rb->chain[0].hunk = rb->header_out;
    i = 0;

    if (r->header_in->pos < r->header_in->last) {
        rb->chain[i].next = &rb->chain[i + 1];
        i++;
        rb->chain[i].hunk = r->header_in;
    }

    if (rb->temp_file->fd != NGX_INVALID_FILE) {
        if (rb->file_hunk == NULL) {
            ngx_test_null(h, ngx_alloc_hunk(r->pool), NGX_ERROR);

            h->type = NGX_HUNK_FILE;
            h->pos = h->start = h->pre_start = 0;
            h->last = h->end = h->post_end = 0;
            h->file_pos = 0;
            h->file_last = rb->offset;
            h->file = rb->temp_file;
            h->shadow = NULL;
            h->tag = 0;

            rb->file_hunk = h;
        }

        rb->chain[i].next = &rb->chain[i + 1];
        i++;
        rb->chain[i].hunk = rb->file_hunk;
    }

    if (rb->hunk && rb->hunk->pos < rb->hunk->last) {
        rb->chain[i].next = &rb->chain[i + 1];
        i++;
        rb->chain[i].hunk = h;
    }

    rb->chain[i].next = NULL;

    return NGX_OK;
}


int ngx_reinit_client_request_body_hunks(ngx_http_reuqest_t *r)
{
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    if (rb->header_in_pos) {
        r->header_in->pos = rb->header_in_pos;
    }

    if (rb->file_hunk) {
        rb->file_hunk->file_pos = rb->file_hunk->file_start;
    }

    if (rb->hunk) {
        rb->hunk->pos = rb->hunk->start;
    }
}
