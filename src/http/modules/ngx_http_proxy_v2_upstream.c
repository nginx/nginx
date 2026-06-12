
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_module.h>
#include <ngx_http_proxy_v2_frame.h>


#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_upstream_cache(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_get(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_file_cache_t **cache);
static ngx_int_t ngx_http_upstream_cache_send(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_upstream_process_cached_header(
    ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_background_update(
    ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_check_range(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
#endif

static void ngx_http_upstream_init_request(ngx_http_request_t *r);
static void ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev);
static void ngx_http_upstream_connect(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t do_write);
static ngx_int_t ngx_http_upstream_send_request_body(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t do_write);
static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_read_request_handler(ngx_http_request_t *r);
static void ngx_http_proxy_v2_upstream_read_loop(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_upstream_dispatch_read(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_upstream_init_header_buffer(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_header(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_early_hints(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_early_hints_writer(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_intercept_errors(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_trailers(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_send_response(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void
    ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_process_non_buffered(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_non_buffered_output(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_upstream_filter_init(void *data);
static ngx_int_t ngx_http_proxy_v2_upstream_non_buffered_filter(void *data,
    ssize_t bytes);
#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_proxy_v2_copy_cache_header(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
#endif
static ssize_t ngx_http_proxy_v2_conn_recv(ngx_connection_t *c,
    ngx_http_proxy_v2_conn_t *h2c);
#if (NGX_THREADS)
static ngx_int_t ngx_http_upstream_thread_handler(ngx_thread_task_t *task,
    ngx_file_t *file);
static void ngx_http_upstream_thread_event_handler(ngx_event_t *ev);
#endif
static ngx_int_t ngx_http_upstream_output_filter(void *data,
    ngx_chain_t *chain);
static void ngx_http_upstream_process_downstream(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_process_event_pipe(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_store(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_next(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t ft_type);
static void ngx_http_upstream_cleanup(void *data);
static void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc);
static void ngx_http_proxy_v2_init_connection(ngx_http_proxy_v2_conn_t *h2c);
static void ngx_http_proxy_v2_init_connection_writer(ngx_http_request_t *r,
    ngx_http_proxy_v2_conn_t *h2c, ngx_connection_t *c);
#if (NGX_HTTP_CACHE)
static ngx_http_proxy_v2_conn_t *ngx_http_proxy_v2_create_request_connection(
    ngx_http_request_t *r);
#endif
static ngx_http_proxy_v2_conn_t *ngx_http_proxy_v2_create_upstream_connection(
    ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_init_connection_buffer(
    ngx_http_proxy_v2_conn_t *h2c, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_init_upstream_buffer(
    ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_proxy_v2_connection_cleanup(void *data);

static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_upstream_set_local(ngx_http_request_t *r,
  ngx_http_upstream_t *u, ngx_http_upstream_local_t *local);

#if (NGX_HTTP_SSL)
static void ngx_http_upstream_ssl_init_connection(ngx_http_request_t *,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_ssl_handshake_handler(ngx_connection_t *c);
static void ngx_http_upstream_ssl_handshake(ngx_http_request_t *,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_ssl_save_session(ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_ssl_name(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_ssl_certificate(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c);
#endif


static ngx_int_t ngx_http_proxy_v2_event_pipe_process_upstream_buffer(
    ngx_event_pipe_t *p);
static ngx_int_t ngx_http_proxy_v2_event_pipe_get_buf(ngx_event_pipe_t *p,
    ngx_chain_t **chain);
static ngx_int_t ngx_http_proxy_v2_event_pipe_write_downstream(
    ngx_event_pipe_t *p);
static ngx_int_t ngx_http_proxy_v2_event_pipe_write_to_downstream(
    ngx_event_pipe_t *p);
static ngx_int_t ngx_http_proxy_v2_event_pipe_write_chain_to_temp_file(
    ngx_event_pipe_t *p);
static ngx_inline void ngx_http_proxy_v2_event_pipe_remove_shadow_links(
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_v2_event_pipe_drain_chains(ngx_event_pipe_t *p);
static ngx_int_t ngx_http_proxy_v2_upstream_parse_frame(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_upstream_process_next_frame(
    ngx_http_request_t *r, ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b,
    ngx_uint_t body);
static ngx_int_t ngx_http_proxy_v2_upstream_consume_frame(
    ngx_http_request_t *r, ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_upstream_filter_data(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *src);
static ngx_int_t ngx_http_proxy_v2_event_pipe_filter_data(ngx_event_pipe_t *p,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *src);


static ssize_t
ngx_http_proxy_v2_conn_recv(ngx_connection_t *c, ngx_http_proxy_v2_conn_t *h2c)
{
    ssize_t    n;
    size_t     size;
    ngx_buf_t *b;

    b = &h2c->buffer;

    size = b->end - b->last;

    if (size == 0) {
        return NGX_AGAIN;
    }

    n = c->recv(c, b->last, size);

    if (n > 0) {
        b->last += n;
    }

    return n;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_proxy_v2_copy_cache_header(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    size_t                    header;
    ngx_buf_t                *b, *h2b;
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    h2b = &ctx->connection->buffer;

    header = h2b->pos - h2b->start;

    if (header > u->conf->buffer_size) {
        return NGX_ERROR;
    }

    b = &u->buffer;

    if (ngx_http_proxy_v2_init_upstream_buffer(r, u) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memcpy(b->start, h2b->start, header);

    b->pos = b->start + header;
    b->last = b->pos;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_proxy_v2_init_upstream_buffer(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_buf_t  *b;

    b = &u->buffer;

    if (b->start == NULL
        || (size_t) (b->end - b->start) < u->conf->buffer_size)
    {
        b->start = ngx_palloc(r->pool, u->conf->buffer_size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->end = b->start + u->conf->buffer_size;
        b->temporary = 1;
        b->tag = u->output.tag;
    }

    b->pos = b->start;
    b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe(ngx_event_pipe_t *p)
{
    ngx_int_t     rc;
    ngx_uint_t    do_write, flags;
    ngx_event_t  *rev, *wev;

    do_write = 0;

    for ( ;; ) {
        if (do_write) {
            p->log->action = "sending to client";

            rc = ngx_http_proxy_v2_event_pipe_write_to_downstream(p);

            if (rc == NGX_ABORT) {
                return NGX_ABORT;
            }

            if (rc == NGX_BUSY) {
                return NGX_OK;
            }
        }

        p->read = 0;
        p->upstream_blocked = 0;

        p->log->action = "processing upstream buffer";

        if (ngx_http_proxy_v2_event_pipe_process_upstream_buffer(p)
            == NGX_ABORT)
        {
            return NGX_ABORT;
        }

        if (!p->read && !p->upstream_blocked) {
            break;
        }

        do_write = 1;
    }

    if (p->upstream
        && p->upstream->fd != (ngx_socket_t) -1)
    {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? NGX_CLOSE_EVENT : 0;

        if (ngx_handle_read_event(rev, flags) != NGX_OK) {
            return NGX_ABORT;
        }

        if (!rev->delayed) {
            if (rev->active && !rev->ready) {
                ngx_add_timer(rev, p->read_timeout);

            } else if (rev->timer_set) {
                ngx_del_timer(rev);
            }
        }
    }

    if (p->downstream->fd != (ngx_socket_t) -1
        && p->downstream->data == p->output_ctx)
    {
        wev = p->downstream->write;
        if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
            return NGX_ABORT;
        }

        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                ngx_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                ngx_del_timer(wev);
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_write_downstream(ngx_event_pipe_t *p)
{
    ngx_int_t     rc;
    ngx_event_t  *wev;

    p->log->action = "sending to client";

    rc = ngx_http_proxy_v2_event_pipe_write_to_downstream(p);

    if (rc == NGX_ABORT) {
        return NGX_ABORT;
    }

    if (rc == NGX_BUSY) {
        return NGX_BUSY;
    }

    if (p->downstream->fd != (ngx_socket_t) -1
        && p->downstream->data == p->output_ctx)
    {
        wev = p->downstream->write;
        if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
            return NGX_ABORT;
        }

        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                ngx_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                ngx_del_timer(wev);
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_get_buf(ngx_event_pipe_t *p, ngx_chain_t **chain)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (p->free_raw_bufs) {

        /* use the free bufs if they exist */

        cl = p->free_raw_bufs;
        if (p->single_buf) {
            p->free_raw_bufs = p->free_raw_bufs->next;
            cl->next = NULL;
        } else {
            p->free_raw_bufs = NULL;
        }

    } else if (p->allocated < p->bufs.num) {

        /* allocate a new buf if it's still allowed */

        b = ngx_create_temp_buf(p->pool, p->bufs.size);
        if (b == NULL) {
            return NGX_ABORT;
        }

        p->allocated++;

        cl = ngx_alloc_chain_link(p->pool);
        if (cl == NULL) {
            return NGX_ABORT;
        }

        cl->buf = b;
        cl->next = NULL;

    } else if (!p->cacheable
               && p->downstream->data == p->output_ctx
               && p->downstream->write->ready
               && !p->downstream->write->delayed)
    {
        /*
         * if the bufs are not needed to be saved in a cache and
         * a downstream is ready then write the bufs to a downstream
         */

        p->upstream_blocked = 1;

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe downstream ready");

        return NGX_AGAIN;

    } else if (p->cacheable
               || p->temp_file->offset < p->max_temp_file_size)
    {

        /*
         * if it is allowed, then save some bufs from p->in
         * to a temporary file, and add them to a p->out chain
         */

        rc = ngx_http_proxy_v2_event_pipe_write_chain_to_temp_file(p);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe temp offset: %O", p->temp_file->offset);

        if (rc != NGX_OK) {
            return rc;
        }

        cl = p->free_raw_bufs;
        if (p->single_buf) {
            p->free_raw_bufs = p->free_raw_bufs->next;
            cl->next = NULL;
        } else {
            p->free_raw_bufs = NULL;
        }

    } else {

        /* there are no bufs to read in */

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "no pipe bufs to read in");

        return NGX_AGAIN;
    }

    *chain = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_process_upstream_buffer(ngx_event_pipe_t *p)
{
    ngx_int_t     rc;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;
    ngx_http_request_t      *r;
    ngx_http_proxy_v2_ctx_t  *ctx;

    if (p->upstream_eof || p->upstream_error || p->upstream_done
        || p->upstream == NULL)
    {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL) {
        return NGX_ABORT;
    }

    buf = &ctx->connection->buffer;

#if (NGX_THREADS)

    if (p->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe process upstream buffer: aio");
        return NGX_AGAIN;
    }

    if (p->writing) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe process upstream buffer: writing");

        rc = ngx_http_proxy_v2_event_pipe_write_chain_to_temp_file(p);

        if (rc != NGX_OK) {
            return rc;
        }
    }

#endif

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe process upstream buffer: %d",
                   p->upstream->read->ready);

#if (NGX_HAVE_KQUEUE)

    /*
     * kqueue notifies about the end of file or a pending error.  When
     * there is no buffered proxy v2 data, translate it to event pipe state.
     */

    if (buf->pos == buf->last
        && p->upstream->read->available == 0
        && p->upstream->read->pending_eof
#if (NGX_SSL)
        && !p->upstream->ssl
#endif
        )
    {
        p->upstream->read->ready = 0;
        p->upstream->read->eof = 1;
        p->upstream_eof = 1;
        p->read = 1;

        if (p->upstream->read->kq_errno) {
            p->upstream->read->error = 1;
            p->upstream_error = 1;
            p->upstream_eof = 0;

            ngx_log_error(NGX_LOG_ERR, p->log,
                          p->upstream->read->kq_errno,
                          "kevent() reported that upstream "
                          "closed connection");
        }
    }
#endif

    if (!p->upstream_eof && !p->upstream_error && !p->upstream_done) {

        while (ctx->parsed) {
            rc = ngx_http_proxy_v2_upstream_consume_frame(r, ctx);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_DONE) {
                p->upstream_done = 1;
                p->read = 1;
                break;
            }

            if (rc == NGX_ERROR) {
                return NGX_ABORT;
            }

            if (rc == NGX_OK) {
                if (ctx->rest == ctx->padding) {
                    ctx->parsed = 0;
                    continue;
                }

                if (buf->pos == buf->last) {
                    break;
                }

                rc = ngx_http_proxy_v2_event_pipe_filter_data(p, ctx, buf);

                if (rc == NGX_BUSY || rc == NGX_AGAIN) {
                    break;
                }

                if (rc == NGX_DONE) {
                    p->upstream_error = 1;
                    p->read = 1;
                    break;
                }

                if (rc != NGX_OK) {
                    return rc == NGX_ERROR ? NGX_ABORT : rc;
                }

                if (ctx->rest == ctx->padding) {
                    ctx->parsed = 0;

                    if (buf->pos < buf->last) {
                        continue;
                    }
                }

                p->read = 1;
                continue;
            }

            return NGX_ABORT;
        }

        if (buf->pos == buf->last
            && (p->upstream->read->eof || p->upstream->read->error))
        {
            p->read = 1;

            if (p->upstream->read->error) {
                p->upstream_error = 1;

            } else {
                p->upstream_eof = 1;
            }
        }
    }

#if (NGX_DEBUG)

    for (cl = p->busy; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->out; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf out  s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->in; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in   s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->free_raw_bufs; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf free s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe length: %O", p->length);

#endif

    if (p->free_raw_bufs && p->length != -1) {
        cl = p->free_raw_bufs;

        if (cl->buf->last - cl->buf->pos >= p->length) {

            p->free_raw_bufs = cl->next;

            /* STUB */ cl->buf->num = p->num++;

            if (p->input_filter(p, cl->buf) == NGX_ERROR) {
                return NGX_ABORT;
            }

            ngx_free_chain(p->pool, cl);
        }
    }

    if (p->length == 0) {
        p->upstream_done = 1;
        p->read = 1;
    }

    if ((p->upstream_done || p->upstream_eof || p->upstream_error)
        && p->free_raw_bufs)
    {

        /* STUB */ p->free_raw_bufs->buf->num = p->num++;

        if (p->input_filter(p, p->free_raw_bufs->buf) == NGX_ERROR) {
            return NGX_ABORT;
        }

        p->free_raw_bufs = p->free_raw_bufs->next;

        if (p->free_bufs && p->buf_to_file == NULL) {
            for (cl = p->free_raw_bufs; cl; cl = cl->next) {
                if (cl->buf->shadow == NULL) {
                    ngx_pfree(p->pool, cl->buf->start);
                }
            }
        }
    }

    if (p->cacheable && (p->in || p->buf_to_file)) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write chain");

        rc = ngx_http_proxy_v2_event_pipe_write_chain_to_temp_file(p);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
{
    u_char            *prev;
    size_t             bsize;
    ngx_int_t          rc;
    ngx_uint_t         flush, flushed, prev_last_shadow;
    ngx_chain_t       *out, **ll, *cl;
    ngx_connection_t  *downstream;

    downstream = p->downstream;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", downstream->write->ready);

#if (NGX_THREADS)

    if (p->writing) {
        rc = ngx_http_proxy_v2_event_pipe_write_chain_to_temp_file(p);

        if (rc == NGX_ABORT) {
            return NGX_ABORT;
        }
    }

#endif

    flushed = 0;

    for ( ;; ) {
        if (p->downstream_error) {
            return ngx_http_proxy_v2_event_pipe_drain_chains(p);
        }

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {

            /* pass the p->out and p->in chains to the output filter */

            for (cl = p->busy; cl; cl = cl->next) {
                cl->buf->recycled = 0;
            }

            if (p->out) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");

                for (cl = p->out; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->out);

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_http_proxy_v2_event_pipe_drain_chains(p);
                }

                p->out = NULL;
            }

            if (p->writing) {
                break;
            }

            if (p->in) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                for (cl = p->in; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->in);

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_http_proxy_v2_event_pipe_drain_chains(p);
                }

                p->in = NULL;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */

            p->downstream_done = 1;
            break;
        }

        if (downstream->data != p->output_ctx
            || !downstream->write->ready
            || downstream->write->delayed)
        {
            break;
        }

        /* bsize is the size of the busy recycled bufs */

        prev = NULL;
        bsize = 0;

        for (cl = p->busy; cl; cl = cl->next) {

            if (cl->buf->recycled) {
                if (prev == cl->buf->start) {
                    continue;
                }

                bsize += cl->buf->end - cl->buf->start;
                prev = cl->buf->start;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: %uz", bsize);

        out = NULL;

        if (bsize >= (size_t) p->busy_size) {
            flush = 1;
            goto flush;
        }

        flush = 0;
        ll = NULL;
        prev_last_shadow = 1;

        for ( ;; ) {
            if (p->out) {
                cl = p->out;

                if (cl->buf->recycled) {
                    ngx_log_error(NGX_LOG_ALERT, p->log, 0,
                                  "recycled buffer in pipe out chain");
                }

                p->out = p->out->next;

            } else if (!p->cacheable && !p->writing && p->in) {
                cl = p->in;

                ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write buf ls:%d %p %z",
                               cl->buf->last_shadow,
                               cl->buf->pos,
                               cl->buf->last - cl->buf->pos);

                if (cl->buf->recycled && prev_last_shadow) {
                    if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
                        flush = 1;
                        break;
                    }

                    bsize += cl->buf->end - cl->buf->start;
                }

                prev_last_shadow = cl->buf->last_shadow;

                p->in = p->in->next;

            } else {
                break;
            }

            cl->next = NULL;

            if (out) {
                *ll = cl;
            } else {
                out = cl;
            }
            ll = &cl->next;
        }

    flush:

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:%p, f:%ui", out, flush);

        if (out == NULL) {

            if (!flush) {
                break;
            }

            /* a workaround for AIO */
            if (flushed++ > 10) {
                return NGX_BUSY;
            }
        }

        rc = p->output_filter(p->output_ctx, out);

        ngx_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);

        if (rc == NGX_ERROR) {
            p->downstream_error = 1;
            return ngx_http_proxy_v2_event_pipe_drain_chains(p);
        }

        for (cl = p->free; cl; cl = cl->next) {

            if (cl->buf->temp_file) {
                if (p->cacheable || !p->cyclic_temp_file) {
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
                if (ngx_http_proxy_v2_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                    return NGX_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
{
    ssize_t       size, bsize, n;
    ngx_buf_t    *b;
    ngx_uint_t    prev_last_shadow;
    ngx_chain_t  *cl, *tl, *next, *out, **ll, **last_out, **last_free;

#if (NGX_THREADS)

    if (p->writing) {

        if (p->aio) {
            return NGX_AGAIN;
        }

        out = p->writing;
        p->writing = NULL;

        n = ngx_write_chain_to_temp_file(p->temp_file, NULL);

        if (n == NGX_ERROR) {
            return NGX_ABORT;
        }

        goto done;
    }

#endif

    if (p->buf_to_file) {
        out = ngx_alloc_chain_link(p->pool);
        if (out == NULL) {
            return NGX_ABORT;
        }

        out->buf = p->buf_to_file;
        out->next = p->in;

    } else {
        out = p->in;
    }

    if (!p->cacheable) {

        size = 0;
        cl = out;
        ll = NULL;
        prev_last_shadow = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %O", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf ls:%d %p, pos %p, size: %z",
                           cl->buf->last_shadow, cl->buf->start,
                           cl->buf->pos, bsize);

            if (prev_last_shadow
                && ((size + bsize > p->temp_file_write_size)
                    || (p->temp_file->offset + size + bsize
                        > p->max_temp_file_size)))
            {
                break;
            }

            prev_last_shadow = cl->buf->last_shadow;

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);

        if (ll == NULL) {
            return NGX_BUSY;
        }

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

#if (NGX_THREADS)
    if (p->thread_handler) {
        p->temp_file->thread_write = 1;
        p->temp_file->file.thread_task = p->thread_task;
        p->temp_file->file.thread_handler = p->thread_handler;
        p->temp_file->file.thread_ctx = p->thread_ctx;
    }
#endif

    n = ngx_write_chain_to_temp_file(p->temp_file, out);

    if (n == NGX_ERROR) {
        return NGX_ABORT;
    }

#if (NGX_THREADS)

    if (n == NGX_AGAIN) {
        p->writing = out;
        p->thread_task = p->temp_file->file.thread_task;
        return NGX_AGAIN;
    }

done:

#endif

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        n -= p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        out = out->next;
    }

    if (n > 0) {
        /* update previous buffer or add new buffer */

        if (p->out) {
            for (cl = p->out; cl->next; cl = cl->next) { /* void */ }

            b = cl->buf;

            if (b->file_last == p->temp_file->offset) {
                p->temp_file->offset += n;
                b->file_last = p->temp_file->offset;
                goto free;
            }

            last_out = &cl->next;

        } else {
            last_out = &p->out;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ABORT;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->tag = p->tag;

        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += n;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        *last_out = cl;
    }

free:

    for (last_free = &p->free_raw_bufs;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;

        cl->next = p->free;
        p->free = cl;

        b = cl->buf;

        if (b->last_shadow) {

            tl = ngx_alloc_chain_link(p->pool);
            if (tl == NULL) {
                return NGX_ABORT;
            }

            tl->buf = b->shadow;
            tl->next = NULL;

            *last_free = tl;
            last_free = &tl->next;

            b->shadow->pos = b->shadow->start;
            b->shadow->last = b->shadow->start;

            ngx_http_proxy_v2_event_pipe_remove_shadow_links(b->shadow);
        }
    }

    return NGX_OK;
}


static ngx_inline void
ngx_http_proxy_v2_event_pipe_remove_shadow_links(ngx_buf_t *buf)
{
    ngx_buf_t  *b, *next;

    b = buf->shadow;

    if (b == NULL) {
        return;
    }

    while (!b->last_shadow) {
        next = b->shadow;

        b->temporary = 0;
        b->recycled = 0;

        b->shadow = NULL;
        b = next;
    }

    b->temporary = 0;
    b->recycled = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


ngx_int_t
ngx_http_proxy_v2_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(p->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (p->buf_to_file && b->start == p->buf_to_file->start) {
        b->pos = p->buf_to_file->last;
        b->last = p->buf_to_file->last;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    b->shadow = NULL;

    cl->buf = b;

    if (p->free_raw_bufs == NULL) {
        p->free_raw_bufs = cl;
        cl->next = NULL;

        return NGX_OK;
    }

    if (p->free_raw_bufs->buf->pos == p->free_raw_bufs->buf->last) {

        /* add the free buf to the list start */

        cl->next = p->free_raw_bufs;
        p->free_raw_bufs = cl;

        return NGX_OK;
    }

    /* the first free buf is partially filled, thus add the free buf after it */

    cl->next = p->free_raw_bufs->next;
    p->free_raw_bufs->next = cl;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_append_chain(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_chain_t *out)
{
    ngx_connection_t  *c;
    ngx_chain_t      **ll;

    if (out) {
        for (ll = &ctx->pending; *ll; ll = &(*ll)->next) {
            /* void */
        }

        *ll = out;
    }

    c = r->upstream->peer.connection;

    if (ctx->pending || ctx->out || ctx->connection->writer.out
        || (c && c->buffered))
    {
        ctx->output_blocked = 1;

        if (c && c->write->ready) {
            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_AGAIN;
    }

    if (ctx->in) {
        ctx->output_blocked = 1;
        return NGX_AGAIN;
    }

    ctx->output_blocked = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_flush_output(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t  *cl, **ll;

    if (ctx == NULL || ctx->connection == NULL) {
        return NGX_OK;
    }

    if (ctx->out) {
        for (ll = &ctx->pending; *ll; ll = &(*ll)->next) {
            /* void */
        }

        *ll = ctx->out;
        ctx->out = NULL;
    }

    if (ctx->pending == NULL && ctx->connection->writer.out == NULL) {
        if (ctx->in) {
            ctx->output_blocked = 1;
            return NGX_AGAIN;
        }

        ctx->output_blocked = 0;
        return NGX_OK;
    }

    rc = ngx_chain_writer(&ctx->connection->writer, ctx->pending);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->connection->busy,
                            &ctx->pending, ngx_http_proxy_v2_frame_tag);

    for (cl = ctx->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    if (rc == NGX_OK && ctx->in) {
        rc = NGX_AGAIN;
    }

    if (rc == NGX_AGAIN) {
        ctx->output_blocked = 1;

    } else {
        ctx->output_blocked = 0;
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_drain_chains(ngx_event_pipe_t *p)
{
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
                if (ngx_http_proxy_v2_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                    return NGX_ABORT;
                }

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


static ngx_http_upstream_next_t  ngx_http_upstream_next_errors[] = {
    { 500, NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { 502, NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { 503, NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { 504, NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { 403, NGX_HTTP_UPSTREAM_FT_HTTP_403 },
    { 404, NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { 429, NGX_HTTP_UPSTREAM_FT_HTTP_429 },
    { 0, 0 }
};


ngx_int_t
ngx_http_proxy_v2_upstream_create(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u && u->cleanup) {
        r->main->count++;
        ngx_http_upstream_cleanup(r);
    }

    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_ERROR;
    }

    r->upstream = u;

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;

#if (NGX_HTTP_CACHE)
    r->cache = NULL;
#endif

    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    return NGX_OK;
}


void
ngx_http_proxy_v2_upstream_init(ngx_http_request_t *r)
{
    ngx_connection_t     *c;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_upstream_init_request(r);
        return;
    }
#endif

#if (NGX_HTTP_V3)
    if (c->quic) {
        ngx_http_upstream_init_request(r);
        return;
    }
#endif

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    ngx_http_upstream_init_request(r);
}


static void
ngx_http_upstream_init_request(ngx_http_request_t *r)
{
    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_http_cleanup_t             *cln;
    ngx_http_upstream_t            *u;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    if (r->aio) {
        return;
    }

    u = r->upstream;

#if (NGX_HTTP_CACHE)

    if (u->conf->cache) {
        ngx_int_t  rc;

        rc = ngx_http_upstream_cache(r, u);

        if (rc == NGX_BUSY) {
            r->write_event_handler = ngx_http_upstream_init_request;
            return;
        }

        r->write_event_handler = ngx_http_request_empty_handler;

        if (rc == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == NGX_OK) {
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_DECLINED;
                r->cached = 0;
                u->buffer.start = NULL;
                u->cache_status = NGX_HTTP_CACHE_MISS;
                u->request_sent = 1;
            }
        }

        if (rc != NGX_DECLINED) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

#endif

    u->store = u->conf->store;

    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {

        if (r->connection->read->ready) {
            ngx_post_event(r->connection->read, &ngx_posted_events);

        } else {
            if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
        r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_upstream_set_local(r, u, u->conf->local) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    if (u->conf->socket_rcvbuf) {
        u->peer.rcvbuf = (int) u->conf->socket_rcvbuf;
    }

    if (u->conf->socket_sndbuf) {
        u->peer.sndbuf = (int) u->conf->socket_sndbuf;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;

    if (u->output.output_filter == NULL) {
        u->output.output_filter = ngx_chain_writer;
        u->output.filter_ctx = &u->writer;
    }

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {

        r->upstream_states = ngx_array_create(r->pool, 1,
                                            sizeof(ngx_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {

        u->state = ngx_array_push(r->upstream_states);
        if (u->state == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

#if (NGX_HTTP_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_http_upstream_create_round_robin_peer(r, u->resolved)
                != NGX_OK)
            {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_http_upstream_connect(r, u);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->handler = ngx_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "no upstream configuration");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NGX_HTTP_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(r, uscf) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    ngx_http_upstream_connect(r, u);
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t               rc;
    ngx_http_cache_t       *c;
    ngx_http_file_cache_t  *cache;

    c = r->cache;

    if (c == NULL) {

        if (!(r->method & u->conf->cache_methods)) {
            return NGX_DECLINED;
        }

        rc = ngx_http_upstream_cache_get(r, u, &cache);

        if (rc != NGX_OK) {
            return rc;
        }

        if (r->method == NGX_HTTP_HEAD && u->conf->cache_convert_head) {
            u->method = ngx_http_core_get_method;
        }

        if (ngx_http_file_cache_new(r) != NGX_OK) {
            return NGX_ERROR;
        }

        if (u->create_key(r) != NGX_OK) {
            return NGX_ERROR;
        }

        /* TODO: add keys */

        ngx_http_file_cache_create_key(r);

        if (r->cache->header_start + 256 > u->conf->buffer_size) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should be increased to at least %uz",
                          &u->conf->module, u->conf->buffer_size,
                          ngx_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return NGX_DECLINED;
        }

        u->cacheable = 1;

        c = r->cache;

        c->body_start = u->conf->buffer_size;
        c->min_uses = u->conf->cache_min_uses;
        c->file_cache = cache;

        switch (ngx_http_test_predicates(r, u->conf->cache_bypass)) {

        case NGX_ERROR:
            return NGX_ERROR;

        case NGX_DECLINED:
            u->cache_status = NGX_HTTP_CACHE_BYPASS;
            return NGX_DECLINED;

        default: /* NGX_OK */
            break;
        }

        c->lock = u->conf->cache_lock;
        c->lock_timeout = u->conf->cache_lock_timeout;
        c->lock_age = u->conf->cache_lock_age;

        u->cache_status = NGX_HTTP_CACHE_MISS;
    }

    rc = ngx_http_file_cache_open(r);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream cache: %i", rc);

    switch (rc) {

    case NGX_HTTP_CACHE_STALE:

        if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background
            && u->conf->cache_background_update)
        {
            if (ngx_http_upstream_cache_background_update(r, u) == NGX_OK) {
                r->cache->background = 1;
                u->cache_status = rc;
                rc = NGX_OK;

            } else {
                rc = NGX_ERROR;
            }
        }

        break;

    case NGX_HTTP_CACHE_UPDATING:

        if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background)
        {
            u->cache_status = rc;
            rc = NGX_OK;

        } else {
            rc = NGX_HTTP_CACHE_STALE;
        }

        break;

    case NGX_OK:
        u->cache_status = NGX_HTTP_CACHE_HIT;
    }

    switch (rc) {

    case NGX_OK:

        return NGX_OK;

    case NGX_HTTP_CACHE_STALE:

        c->valid_sec = 0;
        c->updating_sec = 0;
        c->error_sec = 0;

        u->buffer.start = NULL;
        u->cache_status = NGX_HTTP_CACHE_EXPIRED;

        break;

    case NGX_DECLINED:

        if (u->buffer.start == NULL
            || (size_t) (u->buffer.end - u->buffer.start)
               < u->conf->buffer_size)
        {
            u->buffer.start = NULL;

        } else {
            u->buffer.pos = u->buffer.start + c->header_start;
            u->buffer.last = u->buffer.pos;
        }

        break;

    case NGX_HTTP_CACHE_SCARCE:

        u->cacheable = 0;

        break;

    case NGX_AGAIN:

        return NGX_BUSY;

    case NGX_ERROR:

        return NGX_ERROR;

    default:

        /* cached NGX_HTTP_BAD_GATEWAY, NGX_HTTP_GATEWAY_TIME_OUT, etc. */

        u->cache_status = NGX_HTTP_CACHE_HIT;

        return rc;
    }

    if (ngx_http_upstream_cache_check_range(r, u) == NGX_DECLINED) {
        u->cacheable = 0;
    }

    r->cached = 0;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_cache_get(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_http_file_cache_t **cache)
{
    ngx_str_t               *name, val;
    ngx_uint_t               i;
    ngx_http_file_cache_t  **caches;

    if (u->conf->cache_zone) {
        *cache = u->conf->cache_zone->data;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, u->conf->cache_value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0
        || (val.len == 3 && ngx_strncmp(val.data, "off", 3) == 0))
    {
        return NGX_DECLINED;
    }

    caches = u->caches->elts;

    for (i = 0; i < u->caches->nelts; i++) {
        name = &caches[i]->shm_zone->shm.name;

        if (name->len == val.len
            && ngx_strncmp(name->data, val.data, val.len) == 0)
        {
            *cache = caches[i];
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "cache \"%V\" not found", &val);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_proxy_v2_upstream_process_cached_header(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t                rc;
    ngx_buf_t               *b;
    ngx_http_proxy_v2_ctx_t  *ctx;
    ngx_uint_t               header_done;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL || ctx->connection == NULL) {
        return NGX_ERROR;
    }

    b = &ctx->connection->buffer;

    for ( ;; ) {

        rc = ngx_http_proxy_v2_upstream_process_next_frame(r, ctx, b, 0);

        if (rc == NGX_AGAIN) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
            return rc;
        }

        if (rc == NGX_DECLINED) {
            continue;
        }

        if (rc != NGX_OK && rc != NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        header_done = (rc == NGX_HTTP_PARSE_HEADER_DONE);

        rc = u->process_header(r);

        if (!header_done) {
            if (rc == NGX_OK) {
                continue;
            }

            if (rc == NGX_ERROR
                || rc == NGX_HTTP_UPSTREAM_INVALID_HEADER)
            {
                return rc;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NGX_HTTP_UPSTREAM_EARLY_HINTS) {
            continue;
        }

        return rc;
    }
}


static ngx_int_t
ngx_http_upstream_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t                  rc;
    ngx_http_cache_t          *c;
    ngx_http_proxy_v2_ctx_t   *ctx;
    ngx_http_proxy_v2_conn_t  *h2c;

    r->cached = 1;
    c = r->cache;

    if (c->header_start == c->body_start) {
        r->http_version = NGX_HTTP_VERSION_9;
        return ngx_http_cache_send(r);
    }

    /* TODO: cache stack */

    h2c = ngx_http_proxy_v2_create_request_connection(r);
    if (h2c == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->connection = h2c;
    ctx->id = 0;
    ctx->send_window = h2c->init_window;
    ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    ctx->header_initialized = 1;

    h2c->buffer = *c->buf;
    h2c->buffer.pos += c->header_start;

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = ngx_http_proxy_v2_upstream_process_cached_header(r, u);

    if (rc == NGX_OK) {

        if (ngx_http_upstream_process_headers(r, u) != NGX_OK) {
            return NGX_DONE;
        }

        return ngx_http_cache_send(r);
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN || rc == NGX_HTTP_UPSTREAM_EARLY_HINTS) {
        rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* rc == NGX_HTTP_UPSTREAM_INVALID_HEADER */

    ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                  "cache file \"%s\" contains invalid header",
                  c->file.name.data);

    /* TODO: delete file */

    return rc;
}


static ngx_int_t
ngx_http_upstream_cache_background_update(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_request_t  *sr;

    if (r == r->main) {
        r->preserve_body = 1;
    }

    if (ngx_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
                            NGX_HTTP_SUBREQUEST_CLONE
                            |NGX_HTTP_SUBREQUEST_BACKGROUND)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->header_only = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_check_range(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    off_t             offset;
    u_char           *p, *start;
    ngx_table_elt_t  *h;

    h = r->headers_in.range;

    if (h == NULL
        || !u->cacheable
        || u->conf->cache_max_range_offset == NGX_MAX_OFF_T_VALUE)
    {
        return NGX_OK;
    }

    if (u->conf->cache_max_range_offset == 0) {
        return NGX_DECLINED;
    }

    if (h->value.len < 7
        || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return NGX_OK;
    }

    p = h->value.data + 6;

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return NGX_DECLINED;
    }

    start = p;

    while (*p >= '0' && *p <= '9') { p++; }

    offset = ngx_atoof(start, p - start);

    if (offset >= u->conf->cache_max_range_offset) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

#endif


static void
ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_uint_t                     run_posted;
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_http_upstream_t           *u;
    ngx_http_upstream_resolved_t  *ur;

    run_posted = ctx->async;

    r = ctx->data;
    c = r->connection;

    u = r->upstream;
    ur = u->resolved;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream resolve: \"%V?%V\"", &r->uri, &r->args);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    u_char      text[NGX_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (ngx_http_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    ngx_http_upstream_connect(r, u);

failed:

    if (run_posted) {
        ngx_http_run_posted_requests(c);
    }
}


static void
ngx_http_upstream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    ngx_http_proxy_v2_upstream_read_loop(r, u);

    ngx_http_run_posted_requests(c);
}


static void
ngx_http_upstream_write_handler(ngx_event_t *ev)
{
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_http_request_t       *r;
    ngx_http_upstream_t      *u;
    ngx_http_proxy_v2_ctx_t  *ctx;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->timedout) {
        u->write_event_handler(r, u);
        ngx_http_run_posted_requests(c);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    for ( ;; ) {
        rc = ngx_http_proxy_v2_flush_output(r, ctx);

        if (rc == NGX_ERROR) {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
            ngx_http_run_posted_requests(c);
            return;
        }

        u->write_event_handler(r, u);

        if (u->peer.connection == NULL) {
            ngx_http_run_posted_requests(c);
            return;
        }

        rc = ngx_http_proxy_v2_flush_output(r, ctx);

        if (rc == NGX_ERROR) {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
            ngx_http_run_posted_requests(c);
            return;
        }

        if (rc != NGX_OK || !u->request_body_blocked) {
            break;
        }
    }

    ngx_http_run_posted_requests(c);
}


static void
ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_upstream_check_broken_connection(r, r->connection->write);
}


static void
ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        return;
    }
#endif

#if (NGX_HTTP_V3)

    if (c->quic) {
        if (c->write->error) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, err,
                        "epoll_wait() reported that client prematurely closed "
                        "connection, so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "epoll_wait() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, err,
                   "http upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
    }
}


static void
ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_proxy_v2_ctx_t   *ctx;
    ngx_http_proxy_v2_conn_t  *h2c;

    r->connection->log->action = "connecting to upstream";

    if (u->state && u->state->response_time == (ngx_msec_t) -1) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(r->upstream_states);
    if (u->state == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->response_time = (ngx_msec_t) -1;
    u->state->connect_time = (ngx_msec_t) -1;
    u->state->header_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (u->upstream && u->upstream->shm_zone
        && (u->upstream->flags & NGX_HTTP_UPSTREAM_MODIFY))
    {
        u->state->peer = ngx_palloc(r->pool,
                                    sizeof(ngx_str_t) + u->peer.name->len);
        if (u->state->peer == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->state->peer->len = u->peer.name->len;
        u->state->peer->data = (u_char *) (u->state->peer + 1);
        ngx_memcpy(u->state->peer->data, u->peer.name->data, u->peer.name->len);

        u->peer.name = u->state->peer;
    }
#endif

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    c = u->peer.connection;

    c->requests++;

    c->data = r;

    c->write->handler = ngx_http_upstream_write_handler;
    c->read->handler = ngx_http_upstream_read_handler;

    u->write_event_handler = ngx_http_upstream_send_request_handler;

    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;

    if (r->connection->tcp_nopush == NGX_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = ngx_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = clcf->sendfile_max_chunk;

    if (u->request_sent || u->response_received) {
        if (ngx_http_upstream_reinit(r, u) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    h2c = ngx_http_proxy_v2_create_upstream_connection(r, u);
    if (h2c == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->connection = h2c;
    ctx->read_phase = ngx_http_proxy_v2_read_phase_header;
    ctx->id = h2c->last_stream_id;
    ctx->send_window = h2c->init_window;
    ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    if (r->request_body
        && r->request_body->buf
        && r->request_body->temp_file
        && r == r->main)
    {
        /*
         * the r->request_body->buf can be reused for one request only,
         * the subrequests should allocate their own temporary bufs
         */

        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;

        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }

    u->request_sent = 0;
    u->request_body_sent = 0;
    u->request_body_blocked = 0;
    u->response_received = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

#if (NGX_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    ngx_http_upstream_send_request(r, u, 1);
}


#if (NGX_HTTP_SSL)

static void
ngx_http_upstream_ssl_init_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;

    if (ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (ngx_ssl_create_connection(u->conf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->ssl_server_name || u->conf->ssl_verify) {
        if (ngx_http_upstream_ssl_name(r, u, c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->conf->ssl_certificate
        && u->conf->ssl_certificate->value.len
        && (u->conf->ssl_certificate->lengths
            || u->conf->ssl_certificate_key->lengths))
    {
        if (ngx_http_upstream_ssl_certificate(r, u, c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    if (u->ssl_alpn_protocol.len) {
        if (SSL_set_alpn_protos(c->ssl->connection, u->ssl_alpn_protocol.data,
                                u->ssl_alpn_protocol.len)
            != 0)
        {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "SSL_set_alpn_protos() failed");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#endif

    if (u->conf->ssl_session_reuse) {
        c->ssl->save_session = ngx_http_upstream_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        /* abbreviated SSL handshake may interact badly with Nagle */

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {

        if (!c->write->timer_set) {
            ngx_add_timer(c->write, u->conf->connect_timeout);
        }

        c->ssl->handler = ngx_http_upstream_ssl_handshake_handler;
        return;
    }

    ngx_http_upstream_ssl_handshake(r, u, c);
}


static void
ngx_http_upstream_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl handshake: \"%V?%V\"",
                   &r->uri, &r->args);

    ngx_http_upstream_ssl_handshake(r, u, u->peer.connection);

    ngx_http_run_posted_requests(c);
}


static void
ngx_http_upstream_ssl_handshake(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_connection_t *c)
{
    long  rc;

    if (c->ssl->handshaked) {

        if (u->conf->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (ngx_ssl_check_host(c, &u->ssl_name) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (!c->ssl->sendfile) {
            c->sendfile = 0;
            u->output.sendfile = 0;
        }

        c->write->handler = ngx_http_upstream_write_handler;
        c->read->handler = ngx_http_upstream_read_handler;

        ngx_http_upstream_send_request(r, u, 1);

        return;
    }

    if (c->write->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

failed:

    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
}


static void
ngx_http_upstream_ssl_save_session(ngx_connection_t *c)
{
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    if (c->idle) {
        return;
    }

    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    u->peer.save_session(&u->peer, u->peer.data);
}


static ngx_int_t
ngx_http_upstream_ssl_name(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_connection_t *c)
{
    u_char     *p, *last;
    ngx_str_t   name;

    if (u->conf->ssl_name) {
        if (ngx_http_complex_value(r, u->conf->ssl_name, &name) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, notably if derived from $proxy_host
     * or $http_host; we have to strip it
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = ngx_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = ngx_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!u->conf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = ngx_pnalloc(r->pool, name.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NGX_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_ssl_certificate(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_str_t  cert, key;

    if (ngx_http_complex_value(r, u->conf->ssl_certificate, &cert)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl cert: \"%s\"", cert.data);

    if (*cert.data == '\0') {
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, u->conf->ssl_certificate_key, &key)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl key: \"%s\"", key.data);

    if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
                                       u->conf->ssl_certificate_cache,
                                       u->conf->ssl_passwords)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    off_t         file_pos;
    ngx_chain_t  *cl;

    if (u->reinit_request(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u->early_hints_length = 0;
    u->keepalive = 0;
    u->error = 0;

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* reinit the request chain */

    file_pos = 0;

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;

        /* there is at most one file */

        if (cl->buf->in_file) {
            cl->buf->file_pos = file_pos;
            file_pos = cl->buf->file_last;
        }
    }

    /* reinit the subrequest's ngx_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return NGX_ERROR;
        }

        u->output.free->buf = u->output.buf;
        u->output.free->next = NULL;

        u->output.buf->pos = u->output.buf->start;
        u->output.buf->last = u->output.buf->start;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

    ngx_memzero(&u->buffer, sizeof(ngx_buf_t));

    return NGX_OK;
}


static void
ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t do_write)
{
    ngx_int_t                 rc, flush_rc;
    ngx_connection_t         *c;
    ngx_http_proxy_v2_ctx_t  *ctx;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

    if (u->state->connect_time == (ngx_msec_t) -1) {
        u->state->connect_time = ngx_current_msec - u->start_time;
    }

    if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    c->log->action = "sending request to upstream";

    rc = ngx_http_upstream_send_request_body(r, u, do_write);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_upstream_finalize_request(r, u, rc);
        return;
    }

    flush_rc = ngx_http_proxy_v2_flush_output(r, ctx);

    if (flush_rc == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (flush_rc == NGX_AGAIN) {
        rc = NGX_AGAIN;
    }

    if (rc == NGX_AGAIN) {
        if (!c->write->ready || u->request_body_blocked) {
            ngx_add_timer(c->write, u->conf->send_timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (c->write->ready && c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
            if (ngx_tcp_push(c->fd) == -1) {
                ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                              ngx_tcp_push_n " failed");
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        }

        if (c->read->ready) {
            ngx_post_event(c->read, &ngx_posted_events);
        }

        return;
    }

    /* rc == NGX_OK */

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    if (!u->conf->preserve_output) {
        u->write_event_handler = ngx_http_upstream_dummy_handler;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!u->request_body_sent) {
        u->request_body_sent = 1;

        if (u->header_sent) {
            return;
        }

        if (u->conf->ignore_input) {
            ngx_http_proxy_v2_upstream_read_loop(r, u);
            return;
        }

        ngx_add_timer(c->read, u->conf->read_timeout);

        if (c->read->ready) {
            ngx_http_proxy_v2_upstream_read_loop(r, u);
            return;
        }
    }
}


static ngx_int_t
ngx_http_upstream_send_request_body(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t do_write)
{
    ngx_int_t                  rc;
    ngx_chain_t               *out, *cl, *ln;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request body");

    if (!r->request_body_no_buffering) {

        /* buffered request body */

        if (!u->request_sent) {
            u->request_sent = 1;
            out = u->request_bufs;

        } else {
            out = NULL;
        }

        rc = ngx_output_chain(&u->output, out);

        if (rc == NGX_AGAIN) {
            u->request_body_blocked = 1;

        } else {
            u->request_body_blocked = 0;
        }

        return rc;
    }

    if (!u->request_sent) {
        u->request_sent = 1;
        out = u->request_bufs;

        if (r->request_body->bufs) {
            for (cl = out; cl->next; cl = cl->next) { /* void */ }
            cl->next = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        c = u->peer.connection;
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            return NGX_ERROR;
        }

        r->read_event_handler = ngx_http_upstream_read_request_handler;

    } else {
        out = NULL;
    }

    for ( ;; ) {

        if (do_write) {
            rc = ngx_output_chain(&u->output, out);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            while (out) {
                ln = out;
                out = out->next;
                ngx_free_chain(r->pool, ln);
            }

            if (rc == NGX_AGAIN) {
                u->request_body_blocked = 1;

            } else {
                u->request_body_blocked = 0;
            }

            if (rc == NGX_OK && !r->reading_body) {
                break;
            }
        }

        if (r->reading_body) {
            /* read client request body */

            rc = ngx_http_read_unbuffered_request_body(r);

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            out = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        /* stop if there is nothing to send */

        if (out == NULL) {
            rc = NGX_AGAIN;
            break;
        }

        do_write = 1;
    }

    if (!r->reading_body) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->read_event_handler =
                                  ngx_http_upstream_rd_check_broken_connection;
        }
    }

    return rc;
}


static void
ngx_http_upstream_send_request_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request handler");

    if (c->write->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

#if (NGX_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    if (u->header_sent && !u->conf->preserve_output) {
        u->write_event_handler = ngx_http_upstream_dummy_handler;

        (void) ngx_handle_write_event(c->write, 0);

        return;
    }

    ngx_http_upstream_send_request(r, u, 1);
}


static void
ngx_http_upstream_read_request_handler(ngx_http_request_t *r)
{
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream read request handler");

    if (c->read->timedout) {
        c->timedout = 1;
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ngx_http_upstream_send_request(r, u, 0);
}


static void
ngx_http_proxy_v2_upstream_read_loop(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t                  n;
    ngx_int_t                rc;
    ngx_buf_t               *b;
    ngx_uint_t               read_eof, recv_again;
    ngx_connection_t        *c;
    ngx_http_proxy_v2_ctx_t  *ctx;

    c = u->peer.connection;
    read_eof = 0;

    for ( ;; ) {

        recv_again = 0;

        ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
        if (ctx == NULL || ctx->connection == NULL) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        b = &ctx->connection->buffer;

        if (b->pos == b->last && !read_eof && !u->conf->ignore_input) {

            if (ctx->read_phase == ngx_http_proxy_v2_read_phase_header
                && !ctx->header_initialized
                && ngx_http_upstream_init_header_buffer(r, u) != NGX_OK)
            {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (c->read->ready && !c->read->eof && !c->read->error) {
                if (ctx->read_phase != ngx_http_proxy_v2_read_phase_header) {
                    b->pos = b->start;
                    b->last = b->start;
                }

                n = ngx_http_proxy_v2_conn_recv(c, ctx->connection);

                if (n == NGX_AGAIN) {
                    recv_again = 1;

                } else if (n == NGX_ERROR || n == 0) {
                    if (n == 0) {
                        c->read->eof = 1;
                        read_eof = 1;
                    }

                    switch (ctx->read_phase) {

                    case ngx_http_proxy_v2_read_phase_header:
                        if (n == 0) {
                            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                          "upstream prematurely closed "
                                          "connection");
                        }

                        ngx_http_upstream_next(r, u,
                                               NGX_HTTP_UPSTREAM_FT_ERROR);
                        return;

                    case ngx_http_proxy_v2_read_phase_non_buffered:
                        if (n == NGX_ERROR) {
                            c->read->error = 1;
                        }

                        read_eof = 1;

                        break;

                    case ngx_http_proxy_v2_read_phase_buffered:
                        if (n == NGX_ERROR) {
                            c->read->error = 1;

                        } else {
                            c->read->eof = 1;
                        }

                        read_eof = 1;

                        break;
                    }

                } else {
                    if (ctx->read_phase
                        != ngx_http_proxy_v2_read_phase_buffered)
                    {
                        u->state->bytes_received += n;

                    } else {
                        u->pipe->read = 1;
                        u->pipe->read_length += n;
                    }

#if (NGX_HTTP_SSL)
                    if (ctx->read_phase == ngx_http_proxy_v2_read_phase_header
                        && u->ssl && c->ssl == NULL)
                    {
                        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                      "upstream prematurely sent response");
                        ngx_http_upstream_next(r, u,
                                               NGX_HTTP_UPSTREAM_FT_ERROR);
                        return;
                    }
#endif

                    u->response_received = 1;
                }
            }
        }

        if (ctx->read_phase != ngx_http_proxy_v2_read_phase_header
            && !ctx->parsed
            && (b->pos < b->last
                || ctx->state >= ngx_http_proxy_v2_st_payload
                || (ctx->read_phase != ngx_http_proxy_v2_read_phase_header
                    && ctx->state < ngx_http_proxy_v2_st_payload
                    && ctx->done)))
        {
            rc = ngx_http_proxy_v2_upstream_parse_frame(r, u, ctx);

            if (rc == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }
        }

        rc = ngx_http_proxy_v2_upstream_dispatch_read(r, u, ctx);

        if (rc == NGX_ERROR || rc == NGX_DONE) {
            return;
        }

        if (rc == NGX_AGAIN) {
            if (!ctx->parsed && !recv_again && !u->conf->ignore_input
                && !(ctx->read_phase != ngx_http_proxy_v2_read_phase_header
                     && ctx->state < ngx_http_proxy_v2_st_payload
                     && ctx->done
                     && (ctx->out || ctx->pending))
                && (b->pos < b->last
                    || (ctx->state == ngx_http_proxy_v2_st_payload
                        && ctx->rest == ctx->padding)
                    || (c->read->ready && b->pos == b->last)))
            {
                continue;
            }

            break;
        }

        if (recv_again) {
            break;
        }

        if (u->peer.connection == NULL) {
            return;
        }

        c = u->peer.connection;
        b = &ctx->connection->buffer;

        if (b->pos < b->last) {
            continue;
        }

        if (!c->read->ready || u->conf->ignore_input) {
            break;
        }
    }
}


static ngx_int_t
ngx_http_proxy_v2_upstream_dispatch_read(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_proxy_v2_ctx_t *ctx)
{
    switch (ctx->read_phase) {

    case ngx_http_proxy_v2_read_phase_header:
        return ngx_http_upstream_process_header(r, u);

    case ngx_http_proxy_v2_read_phase_non_buffered:
        return ngx_http_upstream_process_non_buffered(r, u);

    case ngx_http_proxy_v2_read_phase_buffered:
        return ngx_http_upstream_process_event_pipe(r, u);

    default:
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "invalid proxy v2 upstream read phase: %ui",
                      ctx->read_phase);

        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);

        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_http_upstream_init_header_buffer(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_buf_t               *b;
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL || ctx->connection == NULL) {
        return NGX_ERROR;
    }

    b = &ctx->connection->buffer;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    b->pos = b->start;

#if (NGX_HTTP_CACHE)

    if (r->cache) {
        b->pos += r->cache->header_start;
    }

#endif

    b->last = b->pos;

    ctx->header_initialized = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t                rc;
    ngx_buf_t               *b;
    ngx_connection_t        *c;
    ngx_http_proxy_v2_ctx_t  *ctx;
    u_char                  *pos;
    ngx_uint_t               header_done;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (c->read->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return NGX_DONE;
    }

    if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return NGX_DONE;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL || ctx->connection == NULL) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return NGX_ERROR;
    }

    if (!ctx->header_initialized) {
        if (ngx_http_upstream_init_header_buffer(r, u) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }
    }

    b = &ctx->connection->buffer;

    for ( ;; ) {

        pos = b->pos;

        rc = ngx_http_proxy_v2_upstream_process_next_frame(r, ctx, b, 0);

        if (rc == NGX_AGAIN) {

            /*
             * there can be a lot of window update frames,
             * so we reset buffer if it is empty and we haven't
             * started parsing headers yet
             */

            if (ctx->state < ngx_http_proxy_v2_st_payload
                && !ctx->parsing_headers)
            {
                b->pos = pos;
                b->last = b->pos;
            }

            if (b->last == b->end) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream sent too big header");

                ngx_http_upstream_next(r, u,
                                       NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return NGX_DONE;
            }

            if (b->pos == b->last && c->read->ready && !u->conf->ignore_input)
            {
                return NGX_OK;
            }

            break;
        }

        if (rc == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
            ngx_http_upstream_next(r, u,
                                   NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
            return NGX_DONE;
        }

        if (rc == NGX_DECLINED) {
            continue;
        }

        if (rc != NGX_OK && rc != NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            ngx_http_upstream_next(r, u,
                                   NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
            return NGX_DONE;
        }

        header_done = (rc == NGX_HTTP_PARSE_HEADER_DONE);

        rc = u->process_header(r);

        if (!header_done) {
            if (rc == NGX_OK) {
                continue;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                ngx_http_upstream_next(r, u,
                                       NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return NGX_DONE;
            }

            if (rc == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            ngx_http_upstream_next(r, u,
                                   NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
            return NGX_DONE;
        }

        if (rc == NGX_HTTP_UPSTREAM_EARLY_HINTS) {
            rc = ngx_http_upstream_process_early_hints(r, u);

            if (rc == NGX_OK) {
                continue;
            }

            if (rc == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }
        }

        if (rc != NGX_AGAIN) {
            break;
        }
    }

    if (rc == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return NGX_DONE;
    }

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    /* rc == NGX_OK */

    u->state->header_time = ngx_current_msec - u->start_time;

    if (u->headers_in.status_n >= NGX_HTTP_SPECIAL_RESPONSE) {

        if (ngx_http_upstream_test_next(r, u) == NGX_OK) {
            return NGX_DONE;
        }

        if (ngx_http_upstream_intercept_errors(r, u) == NGX_OK) {
            return NGX_DONE;
        }
    }

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data, NGX_HTTP_UPSTREAM_NOTIFY_HEADER);
    }

    if (ngx_http_upstream_process_headers(r, u) != NGX_OK) {
        return NGX_DONE;
    }

    ngx_http_upstream_send_response(r, u);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_upstream_process_early_hints(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    u_char                   *p;
    ngx_uint_t                i;
    ngx_buf_t                *b;
    ngx_list_part_t          *part;
    ngx_table_elt_t          *h, *ho;
    ngx_connection_t         *c;
    ngx_http_proxy_v2_ctx_t  *ctx;

    c = r->connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    b = &ctx->connection->buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http upstream early hints");

    if (u->conf->pass_early_hints) {

        u->early_hints_length += b->pos - b->start;

        if (u->early_hints_length <= (off_t) u->conf->buffer_size) {

            part = &u->headers_in.headers.part;
            h = part->elts;

            for (i = 0; /* void */; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    h = part->elts;
                    i = 0;
                }

                if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                                  h[i].lowcase_key, h[i].key.len))
                {
                    continue;
                }

                ho = ngx_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return NGX_ERROR;
                }

                *ho = h[i];
            }

            if (ngx_http_send_early_hints(r) == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (c->buffered) {
                if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                    return NGX_ERROR;
                }

                r->write_event_handler = ngx_http_upstream_early_hints_writer;
            }

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "upstream sent too big early hints");
        }
    }

    ngx_http_clean_header(r);

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = b->pos;

    b->pos = b->start;

#if (NGX_HTTP_CACHE)

    if (r->cache) {
        b->pos += r->cache->header_start;
    }

#endif

    b->last = ngx_movemem(b->pos, p, b->last - p);

    return NGX_OK;
}


static void
ngx_http_upstream_early_hints_writer(ngx_http_request_t *r)
{
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream early hints writer");

    c->log->action = "sending early hints to client";

    if (ngx_http_write_filter(r, NULL) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!c->buffered) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->write_event_handler =
                                  ngx_http_upstream_wr_check_broken_connection;

        } else {
            r->write_event_handler = ngx_http_request_empty_handler;
        }
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}


static ngx_int_t
ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_msec_t                 timeout;
    ngx_uint_t                 status, mask;
    ngx_http_upstream_next_t  *un;

    status = u->headers_in.status_n;

    for (un = ngx_http_upstream_next_errors; un->status; un++) {

        if (status != un->status) {
            continue;
        }

        timeout = u->conf->next_upstream_timeout;

        if (u->request_sent
            && (r->method & (NGX_HTTP_POST|NGX_HTTP_LOCK|NGX_HTTP_PATCH)))
        {
            mask = un->mask | NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;

        } else {
            mask = un->mask;
        }

        if (u->peer.tries > 1
            && ((u->conf->next_upstream & mask) == mask)
            && !(u->request_sent && r->request_body_no_buffering)
            && !(timeout && ngx_current_msec - u->peer.start_time >= timeout))
        {
            ngx_http_upstream_next(r, u, un->mask);
            return NGX_OK;
        }

#if (NGX_HTTP_CACHE)

        if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
            && (u->conf->cache_use_stale & un->mask))
        {
            ngx_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, rc);
                return NGX_OK;
            }

            u->cache_status = NGX_HTTP_CACHE_STALE;
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return NGX_OK;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_http_upstream_finalize_request(r, u, rc);
            return NGX_OK;
        }

#endif

        break;
    }

#if (NGX_HTTP_CACHE)

    if (status == NGX_HTTP_NOT_MODIFIED
        && u->cache_status == NGX_HTTP_CACHE_EXPIRED
        && u->conf->cache_revalidate)
    {
        time_t     now, valid, updating, error;
        ngx_int_t  rc;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream not modified");

        now = ngx_time();

        valid = r->cache->valid_sec;
        updating = r->cache->updating_sec;
        error = r->cache->error_sec;

        rc = u->reinit_request(r);

        if (rc != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, rc);
            return NGX_OK;
        }

        u->cache_status = NGX_HTTP_CACHE_REVALIDATED;
        rc = ngx_http_upstream_cache_send(r, u);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (valid == 0) {
            valid = r->cache->valid_sec;
            updating = r->cache->updating_sec;
            error = r->cache->error_sec;
        }

        if (valid == 0) {
            valid = ngx_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                valid = now + valid;
            }
        }

        if (valid) {
            r->cache->valid_sec = valid;
            r->cache->updating_sec = updating;
            r->cache->error_sec = error;

            r->cache->date = now;

            ngx_http_file_cache_update_header(r);
        }

        ngx_http_upstream_finalize_request(r, u, rc);
        return NGX_OK;
    }

#endif

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_intercept_errors(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t                  status;
    ngx_uint_t                 i;
    ngx_table_elt_t           *h, *ho, **ph;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    status = u->headers_in.status_n;

    if (status == NGX_HTTP_NOT_FOUND && u->conf->intercept_404) {
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_NOT_FOUND);
        return NGX_OK;
    }

    if (!u->conf->intercept_errors) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->error_pages == NULL) {
        return NGX_DECLINED;
    }

    err_page = clcf->error_pages->elts;
    for (i = 0; i < clcf->error_pages->nelts; i++) {

        if (err_page[i].status == status) {

            if (status == NGX_HTTP_UNAUTHORIZED
                && u->headers_in.www_authenticate)
            {
                h = u->headers_in.www_authenticate;
                ph = &r->headers_out.www_authenticate;

                while (h) {
                    ho = ngx_list_push(&r->headers_out.headers);

                    if (ho == NULL) {
                        ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return NGX_OK;
                    }

                    *ho = *h;
                    ho->next = NULL;

                    *ph = ho;
                    ph = &ho->next;

                    h = h->next;
                }
            }

#if (NGX_HTTP_CACHE)

            if (r->cache) {

                if (u->headers_in.no_cache || u->headers_in.expired) {
                    u->cacheable = 0;
                }

                if (u->cacheable) {
                    time_t  valid;

                    valid = r->cache->valid_sec;

                    if (valid == 0) {
                        valid = ngx_http_file_cache_valid(u->conf->cache_valid,
                                                          status);
                        if (valid) {
                            r->cache->valid_sec = ngx_time() + valid;
                        }
                    }

                    if (valid) {
                        r->cache->error = status;
                    }
                }

                ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
#endif
            ngx_http_upstream_finalize_request(r, u, status);

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_str_t                       uri, args;
    ngx_uint_t                      i, flags;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    if (u->headers_in.no_cache || u->headers_in.expired) {
        u->cacheable = 0;
    }

    if (u->headers_in.x_accel_redirect
        && !(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT))
    {
        ngx_http_upstream_finalize_request(r, u, NGX_DECLINED);

        part = &u->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            if (h[i].hash == 0) {
                continue;
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
                               h[i].lowcase_key, h[i].key.len);

            if (hh && hh->redirect) {
                if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
                    ngx_http_finalize_request(r,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return NGX_DONE;
                }
            }
        }

        uri = u->headers_in.x_accel_redirect->value;

        if (uri.data[0] == '@') {
            ngx_http_named_location(r, &uri);

        } else {
            ngx_str_null(&args);
            flags = NGX_HTTP_LOG_UNSAFE;

            if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
                ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
                return NGX_DONE;
            }

            if (r->method != NGX_HTTP_HEAD) {
                r->method = NGX_HTTP_GET;
                r->method_name = ngx_http_core_get_method;
            }

            ngx_http_internal_redirect(r, &uri, &args);
        }

        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }

    part = &u->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh) {
            if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_DONE;
            }

            continue;
        }

        if (ngx_http_upstream_copy_header_line(r, &h[i], 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }
    }

    if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
        r->headers_out.server->hash = 0;
    }

    if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
        r->headers_out.date->hash = 0;
    }

    r->headers_out.status = u->headers_in.status_n;
    r->headers_out.status_line = u->headers_in.status_line;

    r->headers_out.content_length_n = u->headers_in.content_length_n;

    r->disable_not_modified = !u->cacheable;

    if (u->conf->force_ranges) {
        r->allow_ranges = 1;
        r->single_range = 1;

#if (NGX_HTTP_CACHE)
        if (r->cached) {
            r->single_range = 0;
        }
#endif
    }

    u->length = -1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_trailers(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h, *ho;

    if (!u->conf->pass_trailers) {
        return NGX_OK;
    }

    part = &u->headers_in.trailers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        ho = ngx_list_push(&r->headers_out.trailers);
        if (ho == NULL) {
            return NGX_ERROR;
        }

        *ho = h[i];
    }

    return NGX_OK;
}


static void
ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_event_pipe_t          *p;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_proxy_v2_ctx_t   *ctx;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
        ngx_http_upstream_finalize_request(r, u, rc);
        return;
    }

    u->header_sent = 1;

    c = r->connection;

    if (r->header_only) {

        if (!u->buffering) {
            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }

        if (!u->cacheable && !u->store) {
            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }

        u->pipe->downstream_error = 1;
    }

    if (r->request_body && r->request_body->temp_file
        && r == r->main && !r->preserve_body
        && !u->conf->preserve_output)
    {
        ngx_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
        r->request_body->temp_file->file.fd = NGX_INVALID_FILE;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (!u->buffering) {

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        if (u->input_filter == NULL) {
            u->input_filter_init =
                                  ngx_http_proxy_v2_upstream_filter_init;
            u->input_filter = ngx_http_proxy_v2_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }

        ctx->read_phase = ngx_http_proxy_v2_read_phase_non_buffered;
        r->write_event_handler =
                             ngx_http_upstream_process_non_buffered_downstream;

        r->limit_rate = 0;
        r->limit_rate_set = 1;

        if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        if (ngx_http_proxy_v2_init_upstream_buffer(r, u) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        ngx_http_proxy_v2_upstream_read_loop(r, u);

        return;
    }

    /* TODO: preallocate event_pipe bufs, look "Content-Length" */

#if (NGX_HTTP_CACHE)

    if (r->cache && r->cache->file.fd != NGX_INVALID_FILE) {
        ngx_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = NGX_INVALID_FILE;
    }

    switch (ngx_http_test_predicates(r, u->conf->no_cache)) {

    case NGX_ERROR:
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;

    case NGX_DECLINED:
        u->cacheable = 0;
        break;

    default: /* NGX_OK */

        if (u->cache_status == NGX_HTTP_CACHE_BYPASS) {

            /* create cache if previously bypassed */

            if (ngx_http_file_cache_create(r) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }
        }

        break;
    }

    if (u->cacheable) {
        time_t  now, valid;

        now = ngx_time();

        valid = r->cache->valid_sec;

        if (valid == 0) {
            valid = ngx_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                r->cache->valid_sec = now + valid;
            }
        }

        if (valid) {
            if (ngx_http_proxy_v2_copy_cache_header(r, u) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }

            r->cache->date = now;
            r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);

            if (u->headers_in.status_n == NGX_HTTP_OK
                || u->headers_in.status_n == NGX_HTTP_PARTIAL_CONTENT)
            {
                r->cache->last_modified = u->headers_in.last_modified_time;

                if (u->headers_in.etag) {
                    r->cache->etag = u->headers_in.etag->value;

                } else {
                    ngx_str_null(&r->cache->etag);
                }

            } else {
                r->cache->last_modified = -1;
                ngx_str_null(&r->cache->etag);
            }

            if (ngx_http_file_cache_set_header(r, u->buffer.start) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }

        } else {
            u->cacheable = 0;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http cacheable: %d", u->cacheable);

    if (u->cacheable == 0 && r->cache) {
        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

    if (r->header_only && !u->cacheable && !u->store) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

#endif

    p = u->pipe;
    b = &ctx->connection->buffer;

    p->output_filter = ngx_http_upstream_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = c;
    p->pool = r->pool;
    p->log = c->log;
    p->cacheable = u->cacheable || u->store;

    p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (p->temp_file == NULL) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    p->temp_file->file.fd = NGX_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;

    if (p->cacheable) {
        p->temp_file->persistent = 1;

#if (NGX_HTTP_CACHE)
        if (r->cache && !r->cache->file_cache->use_temp_path) {
            p->temp_file->path = r->cache->file_cache->path;
            p->temp_file->file.name = r->cache->file.name;
        }
#endif

    } else {
        p->temp_file->log_level = NGX_LOG_WARN;
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

#if (NGX_THREADS)
    if (clcf->aio == NGX_HTTP_AIO_THREADS && clcf->aio_write) {
        p->thread_handler = ngx_http_upstream_thread_handler;
        p->thread_ctx = r;
    }
#endif

    p->preread_size = b->last - b->pos;
    p->read_length = p->preread_size;

    if (u->cacheable) {

        p->buf_to_file = ngx_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        p->buf_to_file->start = u->buffer.start;
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        /* the posted aio operation may corrupt a shadow buffer */
        p->single_buf = 1;
    }

    /* TODO: p->free_bufs = 0 if use ngx_create_chain_of_bufs() */
    p->free_bufs = 1;

    if (u->cacheable) {
        u->buffer.last = u->buffer.pos;
    }

    if (u->conf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data may interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        p->cyclic_temp_file = 1;
        c->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }

    p->read_timeout = u->conf->read_timeout;
    p->send_timeout = clcf->send_timeout;
    p->send_lowat = clcf->send_lowat;

    p->length = -1;

    if (u->input_filter_init
        && u->input_filter_init(p->input_ctx) != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    ctx->read_phase = ngx_http_proxy_v2_read_phase_buffered;
    r->write_event_handler = ngx_http_upstream_process_downstream;

    ngx_http_proxy_v2_upstream_read_loop(r, u);
}


static void
ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_event_t          *wev;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    wev = c->write;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered downstream");

    c->log->action = "sending to client";

    if (wev->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_upstream_process_non_buffered_output(r);

    if (rc == NGX_OK) {
        ngx_http_proxy_v2_upstream_read_loop(r, u);
    }
}


static ngx_int_t
ngx_http_upstream_process_non_buffered(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_buf_t                 *b, *buf;
    ngx_int_t                  rc;
    ngx_uint_t                 do_write, flags;
    ngx_connection_t          *c, *downstream, *upstream;
    ngx_http_proxy_v2_ctx_t   *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    upstream = u->peer.connection;
    c = upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered upstream");

    c->log->action = "reading upstream";

    if (c->read->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
        return NGX_DONE;
    }

    downstream = r->connection;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    if (ctx == NULL || ctx->connection == NULL) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return NGX_ERROR;
    }

    b = &u->buffer;
    buf = &ctx->connection->buffer;

    do_write = u->length == 0 || upstream->read->eof
               || upstream->read->error || u->error;

    for ( ;; ) {

        if (do_write) {

            rc = ngx_http_upstream_process_non_buffered_output(r);
            if (rc == NGX_DONE) {
                return NGX_DONE;
            }

            if (rc == NGX_OK) {

                if (u->length == 0
                    || (upstream->read->eof && u->length == -1))
                {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return NGX_DONE;
                }

                if (upstream->read->eof) {
                    ngx_log_error(NGX_LOG_ERR, upstream->log, 0,
                                  "upstream prematurely closed connection");

                    ngx_http_upstream_finalize_request(r, u,
                                                       NGX_HTTP_BAD_GATEWAY);
                    return NGX_DONE;
                }

                if (upstream->read->error || u->error) {
                    ngx_http_upstream_finalize_request(r, u,
                                                       NGX_HTTP_BAD_GATEWAY);
                    return NGX_DONE;
                }

                b->pos = b->start;
                b->last = b->start;

            } else {
                break;
            }

            do_write = 0;
        }

        while (ctx->parsed) {
            if (u->out_bufs || u->busy_bufs || downstream->buffered) {
                do_write = 1;
                break;
            }

            rc = ngx_http_proxy_v2_upstream_consume_frame(r, ctx);

            if (rc == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return NGX_ERROR;
            }

            if (rc == NGX_DONE) {
                u->length = 0;
                do_write = 1;
                break;
            }

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {
                if (ctx->rest == ctx->padding) {
                    ctx->parsed = 0;
                    continue;
                }

                if (buf->pos == buf->last) {
                    break;
                }

                rc = ngx_http_proxy_v2_upstream_filter_data(r, u, ctx, buf);

                if (rc == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    do_write = 1;
                    break;
                }

                if (ctx->rest == ctx->padding) {
                    ctx->parsed = 0;

                    if (buf->pos < buf->last) {
                        continue;
                    }
                }

                do_write = 1;
                continue;
            }

            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_ERROR;
        }

        if (!do_write) {
            break;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (downstream->data == r) {
        if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
            != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_ERROR;
        }
    }

    if (downstream->write->active && !downstream->write->ready) {
        ngx_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        ngx_del_timer(downstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = NGX_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (ngx_handle_read_event(upstream->read, flags) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return NGX_ERROR;
    }

    if (upstream->read->active && !upstream->read->ready) {
        ngx_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        ngx_del_timer(upstream->read);
    }

    if (u->busy_bufs || downstream->buffered
        || (downstream->write->active && !downstream->write->ready))
    {
        return NGX_AGAIN;
    }

    if (buf->pos < buf->last) {
        return NGX_OK;
    }

    if (upstream->read->eof || upstream->read->error || u->error) {
        return NGX_OK;
    }

    return upstream->read->ready ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_upstream_process_non_buffered_output(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_connection_t          *downstream;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    downstream = r->connection;

    if (u->out_bufs || u->busy_bufs || downstream->buffered) {
        rc = ngx_http_output_filter(r, u->out_bufs);

        if (rc == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_DONE;
        }

        ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
                                &u->out_bufs, u->output.tag);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (downstream->data == r) {
        if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
            != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_DONE;
        }
    }

    if (downstream->write->active && !downstream->write->ready) {
        ngx_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        ngx_del_timer(downstream->write);
    }

    if (u->busy_bufs) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_upstream_filter_init(void *data)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t  *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u->length == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");
        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    if (bytes > u->length) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        cl->buf->last = cl->buf->pos + u->length;
        u->length = 0;

        return NGX_OK;
    }

    u->length -= bytes;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_upstream_parse_frame(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_proxy_v2_ctx_t *ctx)
{
    u_char     *pos;
    ngx_int_t   rc;
    ngx_buf_t  *b;

    if (ctx->parsed) {
        return NGX_OK;
    }

    b = &ctx->connection->buffer;

    for ( ;; ) {

        if (ctx->read_phase != ngx_http_proxy_v2_read_phase_header
            && ctx->state < ngx_http_proxy_v2_st_payload
            && ctx->done
            && b->pos == b->last)
        {
            if (ctx->length > 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed stream");
                ctx->parsed_rc = NGX_ERROR;
                ctx->parsed = 1;
                return NGX_OK;
            }

            /*
             * We have finished parsing the response and the remaining control
             * frames.  If there are unsent control frames, post a write event
             * to send them.
             */

            if (ctx->out || ctx->pending) {
                ngx_post_event(u->peer.connection->write,
                               &ngx_posted_events);
                return NGX_AGAIN;
            }

            if (!u->conf->ignore_input
                && u->peer.connection->read->ready
                && !u->peer.connection->read->eof
                && !u->peer.connection->read->error)
            {
                return NGX_AGAIN;
            }

            if (ctx->in == NULL
                && ctx->out == NULL
                && ctx->pending == NULL
                && ctx->output_closed
                && !ctx->output_blocked
                && !ctx->goaway
                && ctx->state == ngx_http_proxy_v2_st_start)
            {
                u->keepalive = 1;
            }

            ctx->parsed_rc = NGX_DONE;
            ctx->parsed = 1;
            return NGX_OK;
        }

        pos = b->pos;

        rc = ngx_http_proxy_v2_upstream_process_next_frame(r, ctx, b,
                   ctx->read_phase != ngx_http_proxy_v2_read_phase_header);

        if (rc == NGX_AGAIN) {

            /*
             * there can be a lot of window update frames,
             * so we reset buffer if it is empty and we haven't
             * started parsing headers yet
             */

            if (ctx->read_phase == ngx_http_proxy_v2_read_phase_header
                && ctx->state < ngx_http_proxy_v2_st_payload
                && !ctx->parsing_headers)
            {
                b->pos = pos;
                b->last = b->pos;
            }

            if (ctx->read_phase == ngx_http_proxy_v2_read_phase_header
                && b->last == b->end)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too big header");

                ctx->parsed_rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
                ctx->parsed = 1;
                return NGX_OK;
            }

            return NGX_AGAIN;
        }

        if (rc == NGX_DECLINED) {
            continue;
        }

        ctx->parsed_rc = rc;
        ctx->parsed = 1;

        return NGX_OK;
    }
}


static ngx_int_t
ngx_http_proxy_v2_upstream_process_next_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, ngx_uint_t body)
{
    ngx_int_t  rc, prc;

    if (ctx->state < ngx_http_proxy_v2_st_payload) {

        rc = ngx_http_proxy_v2_parse_frame(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            return body ? NGX_ERROR : NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ngx_http_proxy_v2_process_frame_header(r, ctx, body) != NGX_OK) {
            return body ? NGX_ERROR : NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
    }

    rc = ngx_http_proxy_v2_parse_payload(r, ctx, b, body);

    if (rc == NGX_DONE) {
        return NGX_DECLINED;
    }

    if (rc == NGX_AGAIN || rc == NGX_HTTP_PARSE_HEADER_DONE) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        return body ? NGX_ERROR : NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    prc = ngx_http_proxy_v2_process_frame_payload(r, ctx, body);

    if (prc == NGX_AGAIN) {
        return NGX_DECLINED;
    }

    if (!body && prc == NGX_ERROR
        && ctx->type != NGX_HTTP_V2_HEADERS_FRAME
        && ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME)
    {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    return prc;
}


static ngx_int_t
ngx_http_proxy_v2_upstream_consume_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (!ctx->parsed) {
        return NGX_AGAIN;
    }

    rc = ctx->parsed_rc;

    if (rc != NGX_OK
        || ctx->read_phase == ngx_http_proxy_v2_read_phase_header
        || ctx->type != NGX_HTTP_V2_DATA_FRAME)
    {
        ctx->parsed = 0;
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_upstream_filter_data(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *src)
{
    size_t     rest;
    ssize_t    size;
    ngx_buf_t *b;

    b = &u->buffer;

    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
    }

    size = b->end - b->last;
    if (size == 0) {
        return NGX_AGAIN;
    }

    rest = ctx->rest - ctx->padding;
    if (rest == 0) {
        return NGX_OK;
    }

    if (src->pos == src->last) {
        return NGX_AGAIN;
    }

    size = ngx_min(size, (ssize_t) rest);
    size = ngx_min(size, (ssize_t) (src->last - src->pos));

    ngx_memcpy(b->last, src->pos, size);

    if (u->input_filter(u->input_filter_ctx, size) == NGX_ERROR) {
        return NGX_ERROR;
    }

    src->pos += size;
    ctx->rest -= size;
    u->state->response_length += size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_event_pipe_filter_data(ngx_event_pipe_t *p,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *src)
{
    size_t       rest;
    ssize_t      size;
    ngx_int_t    rc;
    ngx_chain_t *chain;

    rest = ctx->rest - ctx->padding;
    if (rest == 0) {
        return NGX_OK;
    }

    if (src->pos == src->last) {
        return NGX_AGAIN;
    }

    size = ngx_min((ssize_t) rest, (ssize_t) (src->last - src->pos));

    if (ctx->length != -1 && size > ctx->length) {
        ngx_log_error(NGX_LOG_ERR, p->log, 0,
                      "upstream sent response body larger than indicated "
                      "content length");
        return NGX_DONE;
    }

    rc = ngx_http_proxy_v2_event_pipe_get_buf(p, &chain);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_proxy_v2_event_pipe_remove_shadow_links(chain->buf);

    size = ngx_min(size, (ssize_t) (chain->buf->end - chain->buf->last));

    ngx_memcpy(chain->buf->last, src->pos, size);

    chain->buf->last += size;
    src->pos += size;
    ctx->rest -= size;

    if (chain->buf->last != chain->buf->end
        && (p->length == -1
            || chain->buf->last - chain->buf->pos < p->length))
    {
        chain->next = p->free_raw_bufs;
        p->free_raw_bufs = chain;

        return NGX_OK;
    }

    /* STUB */ chain->buf->num = p->num++;

    rc = p->input_filter(p, chain->buf);
    ngx_free_chain(p->pool, chain);

    return rc;
}


#if (NGX_THREADS)

static ngx_int_t
ngx_http_upstream_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)
{
    ngx_str_t                  name;
    ngx_event_pipe_t          *p;
    ngx_connection_t          *c;
    ngx_thread_pool_t         *tp;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;
    p = r->upstream->pipe;

    if (r->aio) {
        /*
         * tolerate sendfile() calls if another operation is already
         * running; this can happen due to subrequests, multiple calls
         * of the next body filter from a filter, or in HTTP/2 due to
         * a write event on the main connection
         */

        c = r->connection;

#if (NGX_HTTP_V2)
        if (r->stream) {
            c = r->stream->connection->connection;
        }
#endif

        if (task == c->sendfile_task) {
            return NGX_OK;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);

        if (tp == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return NGX_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = ngx_http_upstream_thread_event_handler;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        return NGX_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;
    p->aio = 1;

    ngx_add_timer(&task->event, 60000);

    return NGX_OK;
}


static void
ngx_http_upstream_thread_event_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream thread: \"%V?%V\"", &r->uri, &r->args);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "thread operation took too long");
        ev->timedout = 0;
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    r->main->blocked--;
    r->aio = 0;

#if (NGX_HTTP_V2)

    if (r->stream) {
        /*
         * for HTTP/2, update write event to make sure processing will
         * reach the main connection to handle sendfile() in threads
         */

        c->write->ready = 1;
        c->write->active = 0;
    }

#endif

    if (r->done || r->main->terminated) {
        /*
         * trigger connection event handler if the subrequest was
         * already finalized (this can happen if the handler is used
         * for sendfile() in threads), or if the request was terminated
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        ngx_http_run_posted_requests(c);
    }
}

#endif


static ngx_int_t
ngx_http_upstream_output_filter(void *data, ngx_chain_t *chain)
{
    ngx_int_t            rc;
    ngx_event_pipe_t    *p;
    ngx_http_request_t  *r;

    r = data;
    p = r->upstream->pipe;

    rc = ngx_http_output_filter(r, chain);

    p->aio = r->aio;

    return rc;
}


static void
ngx_http_upstream_process_downstream(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_event_t          *wev;
    ngx_connection_t     *c;
    ngx_event_pipe_t     *p;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    p = u->pipe;
    wev = c->write;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process downstream");

    c->log->action = "sending to client";

#if (NGX_THREADS)
    p->aio = r->aio;
#endif

    if (wev->timedout) {

        p->downstream_error = 1;
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");

    } else {

        if (wev->delayed) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            }

            return;
        }

        rc = ngx_http_proxy_v2_event_pipe_write_downstream(p);

        if (rc == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        if (rc == NGX_BUSY) {
            return;
        }
    }

    if (ngx_http_upstream_process_request(r, u) == NGX_OK) {
        ngx_http_proxy_v2_upstream_read_loop(r, u);
    }
}


static ngx_int_t
ngx_http_upstream_process_event_pipe(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t         rc;
    ngx_event_t       *rev;
    ngx_event_pipe_t  *p;
    ngx_connection_t  *c;

    c = u->peer.connection;
    p = u->pipe;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upstream");

    c->log->action = "reading upstream";

    if (rev->timedout) {

        p->upstream_error = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");

    } else {

        if (rev->delayed) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream delayed");

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        if (ngx_http_proxy_v2_event_pipe(p) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_ERROR;
        }
    }

    rc = ngx_http_upstream_process_request(r, u);

    if (rc != NGX_OK) {
        return rc;
    }

    if (p->downstream->write->active && !p->downstream->write->ready) {
        return NGX_AGAIN;
    }

    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return NGX_OK;
    }

    if (p->upstream
        && p->upstream->read->ready
        && !p->upstream->read->eof
        && !p->upstream->read->error)
    {
        return NGX_OK;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_upstream_process_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_temp_file_t   *tf;
    ngx_event_pipe_t  *p;

    p = u->pipe;

#if (NGX_THREADS)

    if (p->writing && !p->aio) {

        /*
         * make sure to call ngx_http_proxy_v2_event_pipe()
         * if there is an incomplete aio write
         */

        if (ngx_http_proxy_v2_event_pipe_write_downstream(p) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_DONE;
        }
    }

    if (p->writing) {
        return NGX_AGAIN;
    }

#endif

    if (u->peer.connection) {

        if (u->store) {

            if (p->upstream_eof || p->upstream_done) {

                tf = p->temp_file;

                if (u->headers_in.status_n == NGX_HTTP_OK
                    && (p->upstream_done || p->length == -1)
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n == tf->offset))
                {
                    ngx_http_upstream_store(r, u);
                }
            }
        }

#if (NGX_HTTP_CACHE)

        if (u->cacheable) {

            if (p->upstream_done) {
                ngx_http_file_cache_update(r, p->temp_file);

            } else if (p->upstream_eof) {

                tf = p->temp_file;

                if (p->length == -1
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n
                           == tf->offset - (off_t) r->cache->body_start))
                {
                    ngx_http_file_cache_update(r, tf);

                } else {
                    ngx_http_file_cache_free(r->cache, tf);
                }

            } else if (p->upstream_error) {
                ngx_http_file_cache_free(r->cache, p->temp_file);
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http upstream exit: %p", p->out);

            if (p->upstream_done
                || (p->upstream_eof && p->length == -1))
            {
                ngx_http_upstream_finalize_request(r, u, 0);
                return NGX_DONE;
            }

            if (p->upstream_eof) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed connection");
            }

            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return NGX_DONE;
        }
    }

    if (p->downstream_error) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream downstream error");

        if (!u->cacheable && !u->store && u->peer.connection) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return NGX_DONE;
        }
    }

    return NGX_OK;
}


static void
ngx_http_upstream_store(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    size_t                  root;
    time_t                  lm;
    ngx_str_t               path;
    ngx_temp_file_t        *tf;
    ngx_ext_rename_file_t   ext;

    tf = u->pipe->temp_file;

    if (tf->file.fd == NGX_INVALID_FILE) {

        /* create file for empty 200 response */

        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return;
        }

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = u->conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;

        if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                 tf->persistent, tf->clean, tf->access)
            != NGX_OK)
        {
            return;
        }

        u->pipe->temp_file = tf;
    }

    ext.access = u->conf->store_access;
    ext.path_access = u->conf->store_access;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (u->headers_in.last_modified) {

        lm = ngx_parse_http_time(u->headers_in.last_modified->value.data,
                                 u->headers_in.last_modified->value.len);

        if (lm != NGX_ERROR) {
            ext.time = lm;
            ext.fd = tf->file.fd;
        }
    }

    if (u->conf->store_lengths == NULL) {

        if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            return;
        }

    } else {
        if (ngx_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
                                u->conf->store_values->elts)
            == NULL)
        {
            return;
        }
    }

    path.len--;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream stores \"%s\" to \"%s\"",
                   tf->file.name.data, path.data);

    if (path.len == 0) {
        return;
    }

    (void) ngx_ext_rename_file(&tf->file.name, &path, &ext);

    u->store = 0;
}


static void
ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream dummy handler");
}


static void
ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_msec_t  timeout;
    ngx_uint_t  status, state;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xi", ft_type);

    if (u->peer.sockaddr) {

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }

        if (ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_403
            || ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404)
        {
            state = NGX_PEER_NEXT;

        } else {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;

#if (NGX_HTTP_UPSTREAM_SID)
        u->peer.sid = NULL;
#endif
    }

    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) {
        /* TODO: inform balancer instead */
        u->peer.tries++;
    }

    switch (ft_type) {

    case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
    case NGX_HTTP_UPSTREAM_FT_HTTP_504:
        status = NGX_HTTP_GATEWAY_TIME_OUT;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_500:
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_503:
        status = NGX_HTTP_SERVICE_UNAVAILABLE;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_403:
        status = NGX_HTTP_FORBIDDEN;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_404:
        status = NGX_HTTP_NOT_FOUND;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_429:
        status = NGX_HTTP_TOO_MANY_REQUESTS;
        break;

    /*
     * NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING
     * never reach here
     */

    default:
        status = NGX_HTTP_BAD_GATEWAY;
    }

    if (r->connection->error) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    u->state->status = status;

    timeout = u->conf->next_upstream_timeout;

    if (u->request_sent
        && (r->method & (NGX_HTTP_POST|NGX_HTTP_LOCK|NGX_HTTP_PATCH)))
    {
        ft_type |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
    }

    if (u->peer.tries == 0
        || ((u->conf->next_upstream & ft_type) != ft_type)
        || (u->request_sent && r->request_body_no_buffering)
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
#if (NGX_HTTP_CACHE)

        if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & ft_type) || r->cache->stale_error))
        {
            ngx_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, rc);
                return;
            }

            u->cache_status = NGX_HTTP_CACHE_STALE;
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }
#endif

        ngx_http_upstream_finalize_request(r, u, status);
        return;
    }

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (NGX_HTTP_SSL)

        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            u->peer.connection->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(u->peer.connection);
        }
#endif

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

    ngx_http_upstream_connect(r, u);
}


static void
ngx_http_upstream_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    ngx_http_upstream_finalize_request(r, r->upstream, NGX_DONE);
}


static void
ngx_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc)
{
    ngx_uint_t  flush;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    if (u->cleanup == NULL) {
        /* the request was already finalized */
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    *u->cleanup = NULL;
    u->cleanup = NULL;

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_time == (ngx_msec_t) -1) {
        u->state->response_time = ngx_current_msec - u->start_time;

        if (u->pipe && u->pipe->read_length) {
            u->state->bytes_received += u->pipe->read_length
                                        - u->pipe->preread_size;
            u->state->response_length = u->pipe->read_length;
        }

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }
    }

    u->finalize_request(r, rc);

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;

#if (NGX_HTTP_UPSTREAM_SID)
        u->peer.sid = NULL;
#endif
    }

    if (u->peer.connection) {

#if (NGX_HTTP_SSL)

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {

            /*
             * We send the "close notify" shutdown alert to the upstream only
             * and do not wait its "close notify" shutdown alert.
             * It is acceptable according to the TLS standard.
             */

            u->peer.connection->ssl->no_wait_shutdown = 1;

            (void) ngx_ssl_shutdown(u->peer.connection);
        }
#endif

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe) {
        u->pipe->upstream = NULL;
    }

    if (u->pipe && u->pipe->temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file
        && u->pipe->temp_file->file.fd != NGX_INVALID_FILE)
    {
        if (ngx_delete_file(u->pipe->temp_file->file.name.data)
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }

#if (NGX_HTTP_CACHE)

    if (r->cache) {

        if (u->cacheable) {

            if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT) {
                time_t  valid;

                valid = ngx_http_file_cache_valid(u->conf->cache_valid, rc);

                if (valid) {
                    r->cache->valid_sec = ngx_time() + valid;
                    r->cache->error = rc;
                }
            }
        }

        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

#endif

    r->read_event_handler = ngx_http_block_reading;

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (!u->header_sent
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST)
    {
        ngx_http_finalize_request(r, rc);
        return;
    }

    flush = 0;

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        rc = NGX_ERROR;
        flush = 1;
    }

    if (r->header_only
        || (u->pipe && u->pipe->downstream_error))
    {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (rc == 0) {

        if (ngx_http_upstream_process_trailers(r, u) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        rc = ngx_http_send_special(r, NGX_HTTP_LAST);

    } else if (flush) {
        r->keepalive = 0;
        rc = ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_proxy_v2_init_connection(ngx_http_proxy_v2_conn_t *h2c)
{
    ngx_memzero(h2c, sizeof(ngx_http_proxy_v2_conn_t));

    h2c->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    h2c->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    h2c->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    h2c->last_stream_id = 1;
}


static void
ngx_http_proxy_v2_init_connection_writer(ngx_http_request_t *r,
    ngx_http_proxy_v2_conn_t *h2c, ngx_connection_t *c)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (h2c->writer.connection != c) {
        h2c->writer.out = NULL;
        h2c->writer.last = &h2c->writer.out;
        h2c->busy = NULL;
    }

    h2c->writer.connection = c;
    h2c->writer.pool = c->pool ? c->pool : r->pool;
    h2c->writer.limit = clcf->sendfile_max_chunk;
}


#if (NGX_HTTP_CACHE)

static ngx_http_proxy_v2_conn_t *
ngx_http_proxy_v2_create_request_connection(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t        *cln;
    ngx_http_proxy_v2_conn_t  *h2c;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_proxy_v2_conn_t));
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_proxy_v2_connection_cleanup;

    h2c = cln->data;
    ngx_http_proxy_v2_init_connection(h2c);
    ngx_http_proxy_v2_init_connection_writer(r, h2c, r->connection);

    return h2c;
}

#endif


static ngx_http_proxy_v2_conn_t *
ngx_http_proxy_v2_create_upstream_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_pool_cleanup_t        *cln;
    ngx_peer_connection_t     *pc;
    ngx_http_proxy_v2_conn_t  *h2c;

    pc = &u->peer;
    c = pc->connection;

    if (c == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no upstream connection for proxy http2 connection");
        return NULL;
    }

    if (pc->cached) {

        /*
         * for cached connections, connection can be found
         * in the cleanup handler
         */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_proxy_v2_connection_cleanup) {
                h2c = cln->data;
                goto found;
            }
        }

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "no connection found for keepalive http2 connection");
        return NULL;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_proxy_v2_conn_t));
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_proxy_v2_connection_cleanup;

    h2c = cln->data;
    ngx_http_proxy_v2_init_connection(h2c);

    goto init_buffer;

found:

    h2c->last_stream_id += 2;

init_buffer:

    ngx_http_proxy_v2_init_connection_writer(r, h2c, c);

    rc = ngx_http_proxy_v2_init_connection_buffer(h2c, u);
    if (rc != NGX_OK) {
        return NULL;
    }

    return h2c;
}


static ngx_int_t
ngx_http_proxy_v2_init_connection_buffer(ngx_http_proxy_v2_conn_t *h2c,
    ngx_http_upstream_t *u)
{
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    b = &h2c->buffer;

    if (b->start != NULL
        && (size_t) (b->end - b->start) >= u->conf->buffer_size)
    {
        return NGX_OK;
    }

    c = u->peer.connection;

    b->start = ngx_palloc(c->pool, u->conf->buffer_size);
    if (b->start == NULL) {
        return NGX_ERROR;
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->start + u->conf->buffer_size;
    b->temporary = 1;
    b->tag = u->output.tag;

    return NGX_OK;
}


static void
ngx_http_proxy_v2_connection_cleanup(void *data)
{
#if 0
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http proxy cleanup");
#endif
    return;
}


static ngx_int_t
ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
        ho->next = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_set_local(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_http_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        u->peer.local = NULL;
        return NGX_OK;
    }

    addr = ngx_palloc(r->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        u->peer.local = NULL;
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}
