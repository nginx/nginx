
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_event_t *rev);


ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
                                            size_t request_buffer_size)
{
    ssize_t       size;
    ngx_hunk_t   *h;
    ngx_chain_t  *cl;

    size = r->header_in->last - r->header_in->pos;

    if (size) {
        ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);

        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
        h->start = h->pos = r->header_in->pos;
        h->end = h->last = r->header_in->last;

        ngx_alloc_link_and_set_hunk(r->request_hunks, h, r->pool, NGX_ERROR);

        if (size >= r->headers_in.content_length_n) {
            r->header_in->pos += r->headers_in.content_length_n;

            return NGX_OK;
        }

        r->header_in->pos = r->header_in->last;
    }

    r->request_body_len = r->headers_in.content_length_n - size;

    if (r->request_body_len < request_buffer_size + (request_buffer_size >> 2))
    {
        size = r->request_body_len;

    } else {
        size = request_buffer_size;
    }

    ngx_test_null(r->request_body_hunk, ngx_create_temp_hunk(r->pool, size),
                  NGX_ERROR);

    r->connection->read->event_handler =
                                     ngx_http_read_client_request_body_handler;

    ngx_http_read_client_request_body_handler(r->connection->read);

    ngx_alloc_link_and_set_hunk(cl, r->request_body_hunk, r->pool,
                                NGX_ERROR);

    if (r->request_hunks) {
        r->request_hunks->next = cl;

    } else {
        r->request_hunks = cl;
    }

    if (r->request_body_len) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void ngx_http_read_client_request_body_handler(ngx_event_t *rev)
{
    size_t                     size;
    ssize_t                    n;
    ngx_hunk_t                *h;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    c = rev->data;
    r = c->data;

    if (r->request_body_hunk->end - r->request_body_hunk->last == 0) {
        n = ngx_write_chain_to_temp_file(r->temp_file,
                               r->request_hunks->next ? r->request_hunks->next:
                                                        r->request_hunks);
        /* TODO: n == 0 or not complete and level event */

        if (n == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->temp_file->offset += n;

        r->request_body_hunk->pos = r->request_body_hunk->start;
        r->request_body_hunk->last = r->request_body_hunk->start;
    }

    size = r->request_body_hunk->end - r->request_body_hunk->last;

    if (size > r->request_body_len) {
        size = r->request_body_len;
    }

    n = ngx_recv(c, r->request_body_hunk->last, size);

    if (n == NGX_AGAIN) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_add_timer(rev, clcf->client_body_timeout);

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed prematurely connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    r->request_body_hunk->last += n;
    r->request_body_len -= n;

    if (r->request_body_len) {
        return;
    }

    if (r->temp_file->file.fd != NGX_INVALID_FILE) {

        /* save the last part */
        n = ngx_write_chain_to_temp_file(r->temp_file,
                               r->request_hunks->next ? r->request_hunks->next:
                                                        r->request_hunks);
        /* TODO: n == 0 or not complete and level event */

        if (n == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        h = ngx_calloc_hunk(r->pool);
        if (h == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        h->type = NGX_HUNK_FILE;
        h->file_pos = 0;
        h->file_last = r->temp_file->file.offset;
        h->file = &r->temp_file->file;

        if (r->request_hunks->next) {
            r->request_hunks->next->hunk = h;

        } else {
            r->request_hunks->hunk = h;
        }
    }

    r->request_body_handler(r->data);
}
