
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_event_t *rev);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);


ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r)
{
    ssize_t                    size;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_core_loc_conf_t  *clcf;

    size = r->header_in->last - r->header_in->pos;

    if (size) {

        /* there is the pre-read part of the request body */

        ngx_test_null(b, ngx_calloc_buf(r->pool),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        b->temporary = 1;
        b->start = b->pos = r->header_in->pos;
        b->end = b->last = r->header_in->last;

        ngx_alloc_link_and_set_buf(r->request_body->bufs, b, r->pool,
                                    NGX_HTTP_INTERNAL_SERVER_ERROR);

        if (size >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;

            r->request_body->handler(r->request_body->data);

            return NGX_OK;
        }

        r->header_in->pos = r->header_in->last;
    }


    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    r->request_body->rest = r->headers_in.content_length_n - size;

    if (r->request_body->rest
                             < clcf->client_body_buffer_size
                                        + (clcf->client_body_buffer_size >> 2))
    {
        size = r->request_body->rest;

    } else {
        size = clcf->client_body_buffer_size;
    }

    ngx_test_null(r->request_body->buf, ngx_create_temp_buf(r->pool, size),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    ngx_alloc_link_and_set_buf(cl, r->request_body->buf, r->pool,
                               NGX_HTTP_INTERNAL_SERVER_ERROR);

    if (r->request_body->bufs) {
        r->request_body->bufs->next = cl;

    } else {
        r->request_body->bufs = cl;
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

    if (rev->timedout) {
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        if (r->request_body->buf->last == r->request_body->buf->end) {
            n = ngx_write_chain_to_temp_file(r->request_body->temp_file,
                     r->request_body->bufs->next ? r->request_body->bufs->next:
                                                   r->request_body->bufs);

            /* TODO: n == 0 or not complete and level event */

            if (n == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body->temp_file->offset += n;

            r->request_body->buf->pos = r->request_body->buf->start;
            r->request_body->buf->last = r->request_body->buf->start;
        }

        size = r->request_body->buf->end - r->request_body->buf->last;

        if (size > r->request_body->rest) {
            size = r->request_body->rest;
        }

        n = c->recv(c, r->request_body->buf->last, size);

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
            r->closed = 1;
            return NGX_HTTP_BAD_REQUEST;
        }

        r->request_body->buf->last += n;
        r->request_body->rest -= n;

        if (r->request_body->rest == 0) {
            break;
        }

        if (r->request_body->buf->last < r->request_body->buf->end) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http client request body rest " SIZE_T_FMT,
                   r->request_body->rest);

    if (r->request_body->rest) {
        return NGX_AGAIN;
    }

    if (r->request_body->temp_file->file.fd != NGX_INVALID_FILE) {

        /* save the last part */
        n = ngx_write_chain_to_temp_file(r->request_body->temp_file,
                     r->request_body->bufs->next ? r->request_body->bufs->next:
                                                   r->request_body->bufs);

        /* TODO: n == 0 or not complete and level event */

        if (n == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (!(b = ngx_calloc_buf(r->pool))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->in_file = 1;
        b->file_pos = 0;
        b->file_last = r->request_body->temp_file->file.offset;
        b->file = &r->request_body->temp_file->file;

        if (r->request_body->bufs->next) {
            r->request_body->bufs->next->buf = b;

        } else {
            r->request_body->bufs->buf = b;
        }
    }

    r->request_body->handler(r->request_body->data);

    return NGX_OK;
}
