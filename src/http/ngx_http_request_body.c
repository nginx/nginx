
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


int ngx_http_init_client_request_body(ngx_http_request_t *r, int size)
{
    int                       header_in_part, len;
    ngx_hunk_t               *h;
    ngx_http_request_body_t  *rb;

    ngx_test_null(rb, ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    header_in_part = r->header_in->end - r->header_in->pos;

    if (header_in_part) {
        rb->header_in_pos = r->header_in->pos;
    }

    if (header_in_part > r->headers_in.content_length_n) {
        header_in_part = r->headers_in.content_length_n;

    } else {
        len = r->headers_in.content_length_n - header_in_part;
        if (len > size) {
            len = size;

        } else if (len > NGX_PAGE_SIZE) {
            len = ((len + NGX_PAGE_SIZE - 1) / NGX_PAGE_SIZE) * NGX_PAGE_SIZE;
        }

        if (len) {
            ngx_test_null(rb->hunk, ngx_create_temp_hunk(r->pool, len, 0, 0),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    r->request_body = rb;

    return NGX_OK;
}


int ngx_http_read_client_request_body(ngx_http_request_t *r)
{
    int                       size, n, rc;
    ngx_chain_t              *entry;
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

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

        n = ngx_recv_chain(r->connection, rb->chain);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        for (entry = rb->chain; entry; entry = entry->next) {
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
            if (rb->temp_file.fd == NGX_INVALID_FILE) {
                rc = ngx_create_temp_file(&rb->temp_file, rb->temp_path,
                                          r->pool, 0);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    return NGX_AGAIN;
                }
            }

            n = ngx_write_file(&rb->temp_file, rb->hunk->pos,
                               rb->hunk->last - rb->hunk->pos, rb->offset);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            rb->offset += n;
            rb->hunk->last = rb->hunk->pos;
        }

    } while (r->connection->read->ready);

    return NGX_OK;
}


int ngx_http_init_client_request_body_chain(ngx_http_request_t *r)
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

    if (rb->temp_file.fd != NGX_INVALID_FILE) {

        if (rb->file_hunk == NULL) {
            ngx_test_null(h, ngx_alloc_hunk(r->pool), NGX_ERROR);

            h->type = NGX_HUNK_FILE;
            h->pos = h->start = h->pre_start = 0;
            h->last = h->end = h->post_end = 0;
            h->file_pos = 0;
            h->file_last = rb->offset;
            h->file = &rb->temp_file;
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


void ngx_http_reinit_client_request_body_hunks(ngx_http_request_t *r)
{
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    if (rb->header_in_pos) {
        r->header_in->pos = rb->header_in_pos;
    }

    if (rb->file_hunk) {
        rb->file_hunk->file_pos = 0;
    }

    if (rb->hunk) {
        rb->hunk->pos = rb->hunk->start;
    }
}
