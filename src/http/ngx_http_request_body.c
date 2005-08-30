
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);

/*
 * on completion ngx_http_read_client_request_body() adds to
 * r->request_body->bufs one or two bufs:
 *    *) one memory buf that was preread in r->header_in;
 *    *) one memory or file buf that contains the rest of the body
 */

ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)

{
    ssize_t                    size;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->request_body || r->discard_body) {
        post_handler(r);
        return NGX_OK;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body = rb;

    if (r->headers_in.content_length_n <= 0) {
        post_handler(r);
        return NGX_OK;
    }

    rb->post_handler = post_handler;

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */

    size = r->header_in->last - r->header_in->pos;

    if (size) {

        /* there is the pre-read part of the request body */

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->start = b->pos = r->header_in->pos;
        b->end = b->last = r->header_in->last;

        rb->bufs = ngx_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;

        if (size >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            post_handler(r);

            return NGX_OK;
        }

        r->header_in->pos = r->header_in->last;
        r->request_length += size;
    }


    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    rb->rest = r->headers_in.content_length_n - size;

    if (rb->rest < clcf->client_body_buffer_size
                                        + (clcf->client_body_buffer_size >> 2))
    {
        size = rb->rest;

    } else {
        size = clcf->client_body_buffer_size;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (rb->bufs) {
        rb->bufs->next = cl;

    } else {
        rb->bufs = cl;
    }

    r->read_event_handler = ngx_http_read_client_request_body_handler;

    return ngx_http_do_read_client_request_body(r);
}


static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->connection->read->timedout) {
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_temp_file_t           *tf;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        if (rb->buf->last == rb->buf->end) {

            if (rb->temp_file == NULL) {
                tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
                if (tf == NULL) {
                    return NGX_ERROR;
                }

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                tf->file.fd = NGX_INVALID_FILE;
                tf->file.log = r->connection->log;
                tf->path = clcf->client_body_temp_path;
                tf->pool = r->pool;
                tf->warn = "a client request body is buffered "
                           "to a temporary file";

                rb->temp_file = tf;

            }

            n = ngx_write_chain_to_temp_file(rb->temp_file,
                                             rb->bufs->next ? rb->bufs->next:
                                                              rb->bufs);

            /* TODO: n == 0 or not complete and level event */

            if (n == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->temp_file->offset += n;
            rb->buf->last = rb->buf->start;
        }

        size = rb->buf->end - rb->buf->last;

        if (size > rb->rest) {
            size = rb->rest;
        }

        n = c->recv(c, rb->buf->last, size);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body recv %z", n);

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
            c->closed = 1;
            return NGX_HTTP_BAD_REQUEST;
        }

        rb->buf->last += n;
        rb->rest -= n;
        r->request_length += n;

        if (rb->rest == 0) {
            break;
        }

        if (rb->buf->last < rb->buf->end) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http client request body rest %uz", rb->rest);

    if (rb->rest) {
        return NGX_AGAIN;
    }

    if (rb->temp_file) {

        /* save the last part */

        n = ngx_write_chain_to_temp_file(rb->temp_file,
                                         rb->bufs->next ? rb->bufs->next:
                                                          rb->bufs);

        /* TODO: n == 0 or not complete and level event */

        if (n == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->in_file = 1;
        b->file_pos = 0;
        b->file_last = rb->temp_file->file.offset;
        b->file = &rb->temp_file->file;

        if (rb->bufs->next) {
            rb->bufs->next->buf = b;

        } else {
            rb->bufs->buf = b;
        }
    }

    rb->post_handler(r);

    return NGX_OK;
}
