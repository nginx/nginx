
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_event_t *rev);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);


ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
                                            size_t request_buffer_size)
{
    ngx_int_t     rc;
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

    ngx_alloc_link_and_set_hunk(cl, r->request_body_hunk, r->pool,
                                NGX_ERROR);

    if (r->request_hunks) {
        r->request_hunks->next = cl;

    } else {
        r->request_hunks = cl;
    }

    r->connection->read->event_handler =
                                     ngx_http_read_client_request_body_handler;

    return ngx_http_do_read_client_request_body(r);
}


static void ngx_http_read_client_request_body_handler(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = rev->data;
    r = c->data;

    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_hunk_t                *h;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        if (r->request_body_hunk->last == r->request_body_hunk->end) {
            n = ngx_write_chain_to_temp_file(r->temp_file,
                               r->request_hunks->next ? r->request_hunks->next:
                                                        r->request_hunks);

            /* TODO: n == 0 or not complete and level event */

            if (n == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body recv " SIZE_T_FMT, n);

        if (n == NGX_AGAIN) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed prematurely connection");
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_HTTP_BAD_REQUEST;
        }

        r->request_body_hunk->last += n;
        r->request_body_len -= n;

        if (r->request_body_hunk->last < r->request_body_hunk->end) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http client request body left " SIZE_T_FMT,
                   r->request_body_len);

    if (r->request_body_len) {
        return NGX_AGAIN;
    }

    if (r->temp_file->file.fd != NGX_INVALID_FILE) {

        /* save the last part */
        n = ngx_write_chain_to_temp_file(r->temp_file,
                               r->request_hunks->next ? r->request_hunks->next:
                                                        r->request_hunks);

        /* TODO: n == 0 or not complete and level event */

        if (n == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h = ngx_calloc_hunk(r->pool);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

    return NGX_OK;
}
