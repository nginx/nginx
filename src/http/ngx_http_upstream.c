
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_connect.h>


static void ngx_http_upstream_check_broken_connection(ngx_event_t *ev);
static void ngx_http_upstream_connect(ngx_http_request_t *r,
                                      ngx_http_upstream_t *u);
static void ngx_http_upstream_reinit(ngx_http_request_t *r,
                                     ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request(ngx_http_request_t *r,
                                           ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request_handler(ngx_event_t *wev);
static void ngx_http_upstream_process_header(ngx_event_t *rev);
static void ngx_http_upstream_send_response(ngx_http_request_t *r,
                                            ngx_http_upstream_t *u);
static void ngx_http_upstream_process_body(ngx_event_t *ev);
static void ngx_http_upstream_dummy_handler(ngx_event_t *wev);
static void ngx_http_upstream_next(ngx_http_request_t *r,
                                   ngx_http_upstream_t *u,
                                   ngx_uint_t ft_type);
static void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
                                               ngx_http_upstream_t *u,
                                               ngx_int_t rc);

static size_t ngx_http_upstream_log_status_getlen(ngx_http_request_t *r,
                                                  uintptr_t data);
static u_char *ngx_http_upstream_log_status(ngx_http_request_t *r, u_char *buf,
                                            ngx_http_log_op_t *op);


static ngx_int_t ngx_http_upstream_add_log_formats(ngx_conf_t *cf);


ngx_http_module_t  ngx_http_upstream_module_ctx = {
    ngx_http_upstream_add_log_formats,     /* pre conf */
    
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};
    

ngx_module_t  ngx_http_upstream_module = {
    NGX_MODULE,
    &ngx_http_upstream_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static ngx_http_log_op_name_t ngx_http_upstream_log_fmt_ops[] = {
    { ngx_string("upstream_status"), 0, NULL,
                                        ngx_http_upstream_log_status_getlen,
                                        ngx_http_upstream_log_status },
    { ngx_null_string, 0, NULL, NULL, NULL }
};


char *ngx_http_upstream_header_errors[] = {
    "upstream sent invalid header",
    "upstream sent too long header line"
};


void ngx_http_upstream_init(ngx_http_request_t *r)
{
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->read->event_handler = ngx_http_upstream_check_broken_connection;
    
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
    
        c->write->event_handler = ngx_http_upstream_check_broken_connection;

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT,
                                                NGX_CLEAR_EVENT) == NGX_ERROR)
            {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    u = r->upstream;

    u->method = r->method;

    if (u->create_request(r) == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.log = r->connection->log;
    u->saved_log_ctx = r->connection->log->data;
    u->saved_log_handler = r->connection->log->handler;
    r->connection->log->data = u->log_ctx;
    r->connection->log->handler = u->log_handler;

    u->output.sendfile = r->connection->sendfile;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.output_filter = ngx_chain_writer;
    u->output.filter_ctx = &u->writer;

    u->writer.pool = r->pool;

    if (ngx_array_init(&u->states, r->pool, u->peer.peers->number,
                               sizeof(ngx_http_upstream_state_t)) == NGX_ERROR)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!(u->state = ngx_push_array(&u->states))) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    ngx_http_upstream_connect(r, u);
}


static void ngx_http_upstream_check_broken_connection(ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err; 
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d", ev->write);

    c = ev->data;
    r = c->data;
    u = r->upstream;

    if (u->peer.connection == NULL) {
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cachable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client closed "
                          "prematurely connection, "
                          "so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client closed "
                      "prematurely connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    /*
     * we do not need to disable the write event because
     * that event has NGX_USE_CLEAR_EVENT type
     */

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        if (ngx_del_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    ev->eof = 1;

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    if (!u->cachable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client closed prematurely connection, "
                      "so upstream connection is closed too");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client closed prematurely connection");

    if (u->peer.connection == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }
}


static void ngx_http_upstream_connect(ngx_http_request_t *r,
                                      ngx_http_upstream_t *u)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;

    r->connection->log->action = "connecting to upstream";

    r->connection->single_connection = 0;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = &u->peer.peers->peer[u->peer.cur_peer].name;

    if (rc == NGX_CONNECT_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    c = u->peer.connection;

    c->data = r;
    c->write->event_handler = ngx_http_upstream_send_request_handler;
    c->read->event_handler = ngx_http_upstream_process_header;

    c->sendfile = r->connection->sendfile;

    c->pool = r->pool;
    c->read->log = c->write->log = c->log = r->connection->log;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = 0;

    if (u->request_sent) {
        ngx_http_upstream_reinit(r, u);
    }

    if (r->request_body->buf) {
        if (r->request_body->temp_file) {

            if (!(u->output.free = ngx_alloc_chain_link(r->pool))) {
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

        } else {
            r->request_body->buf->pos = r->request_body->buf->start;
        }
    }

    u->request_sent = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    /* rc == NGX_OK */

    ngx_http_upstream_send_request(r, u);
}


static void ngx_http_upstream_reinit(ngx_http_request_t *r,
                                     ngx_http_upstream_t *u)
{
    ngx_chain_t  *cl;

    if (u->reinit_request(r) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* reinit the request chain */
    
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
        cl->buf->file_pos = 0;
    }

    /* reinit the ngx_output_chain() context */

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.free = NULL;
    u->output.busy = NULL;
    
    /* reinit u->header_in buffer */
    
#if 0
    if (u->cache) {
        u->header_in.pos = u->header_in.start + u->cache->ctx.header_size;
        u->header_in.last = u->header_in.pos;

    } else {
        u->header_in.pos = u->header_in.start;
        u->header_in.last = u->header_in.start;
    }
#else
        u->header_in.pos = u->header_in.start;
        u->header_in.last = u->header_in.start;
#endif

    /* add one more state */

    if (!(u->state = ngx_push_array(&u->states))) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    u->status = 0;
    u->status_count = 0;
}


static void ngx_http_upstream_send_request(ngx_http_request_t *r,
                                           ngx_http_upstream_t *u)
{
    int                rc;
    ngx_connection_t  *c;
    
    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT)
        && !u->request_sent
        && c->write->pending_eof)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, c->write->kq_errno,
                      "connect() failed");

        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

#endif

    c->log->action = "sending request to upstream";

    rc = ngx_output_chain(&u->output,
                          u->request_sent ? NULL : r->request_body->bufs);

    u->request_sent = 1;

    if (rc == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->send_timeout);

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) == NGX_ERROR)
        {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    /* rc == NGX_OK */

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return; 
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        return;
    }
    
    ngx_add_timer(c->read, u->conf->read_timeout);

#if 1
    if (c->read->ready) {
    
        /* post aio operation */

        /*
         * TODO comment
         * although we can post aio operation just in the end
         * of ngx_http_upstream_connect() CHECK IT !!!
         * it's better to do here because we postpone header buffer allocation
         */

        ngx_http_upstream_process_header(c->read);
        return;
    }
#endif

    c->write->event_handler = ngx_http_upstream_dummy_handler;

    if (ngx_handle_level_write_event(c->write) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}


static void ngx_http_upstream_send_request_handler(ngx_event_t *wev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    c = wev->data;
    r = c->data;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http upstream send request handler");

    if (wev->timedout) {
        c->log->action = "sending request to upstream";
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (r->connection->write->eof && (!u->cachable || !u->request_sent)) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_upstream_send_request(r, u);
}


static void ngx_http_upstream_process_header(ngx_event_t *rev)
{
    ssize_t               n;
    ngx_int_t             rc;
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    c = rev->data;
    r = c->data;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (rev->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }
    
    if (u->header_in.start == NULL) {
        u->header_in.start = ngx_palloc(r->pool, u->conf->header_buffer_size);
        if (u->header_in.start == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->header_in.pos = u->header_in.start;
        u->header_in.last = u->header_in.start;
        u->header_in.end = u->header_in.start + u->conf->header_buffer_size;
        u->header_in.temporary = 1;

        u->header_in.tag = u->output.tag;

#if 0
        if (u->cache) {
            u->header_in.pos += u->cache->ctx.header_size;
            u->header_in.last = u->header_in.pos;
        }
#endif
    }

    n = ngx_recv(u->peer.connection, u->header_in.last,
                 u->header_in.end - u->header_in.last);

    if (n == NGX_AGAIN) {
#if 0
        ngx_add_timer(rev, u->read_timeout);
#endif

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream prematurely closed connection");
    }

    if (n == NGX_ERROR || n == 0) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->header_in.last += n;

#if 0
    u->valid_header_in = 0;

    u->peer.cached = 0;
#endif

    rc = u->process_header(r);

    if (rc == NGX_AGAIN) {
#if 0
        ngx_add_timer(rev, u->read_timeout);
#endif

        if (u->header_in.last == u->header_in.end) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too big header");

            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
            return;
        }

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }

    if (rc == NGX_ERROR || rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == NGX_OK */

    ngx_http_upstream_send_response(r, u);
}


static void ngx_http_upstream_send_response(ngx_http_request_t *r,
                                            ngx_http_upstream_t *u)
{
    ngx_event_pipe_t          *p;
    ngx_http_core_loc_conf_t  *clcf;


    if (u->send_header(r) == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->header_sent = 1;

    /* TODO: preallocate event_pipe bufs, look "Content-Length" */

#if 0

    if (u->cache && u->cache->ctx.file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(u->cache->ctx.file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          u->cache->ctx.file.name.data);
        }
    }

    if (u->cachable) {
        header = (ngx_http_cache_header_t *) u->header_in->start;

        header->expires = u->cache->ctx.expires;
        header->last_modified = u->cache->ctx.last_modified;
        header->date = u->cache->ctx.date;
        header->length = r->headers_out.content_length_n;
        u->cache->ctx.length = r->headers_out.content_length_n;

        header->key_len = u->cache->ctx.key0.len;
        ngx_memcpy(&header->key, u->cache->ctx.key0.data, header->key_len);
        header->key[header->key_len] = LF;
    }

#endif

    p = &u->pipe;

    p->output_filter = (ngx_event_pipe_output_filter_pt) ngx_http_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;     
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = r->connection;
    p->pool = r->pool;
    p->log = r->connection->log;
    
    p->cachable = u->cachable;

    if (!(p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t)))) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    p->temp_file->file.fd = NGX_INVALID_FILE;
    p->temp_file->file.log = r->connection->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;
    
    if (u->cachable) {
        p->temp_file->persistent = 1;
    } else {
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

    if (!(p->preread_bufs = ngx_alloc_chain_link(r->pool))) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
    p->preread_bufs->buf = &u->header_in;
    p->preread_bufs->next = NULL;
    u->header_in.recycled = 1;

    p->preread_size = u->header_in.last - u->header_in.pos;

    if (u->cachable) {
        p->buf_to_file = ngx_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
        p->buf_to_file->pos = u->header_in.start;
        p->buf_to_file->last = u->header_in.pos;
        p->buf_to_file->temporary = 1;
    }

    if (ngx_event_flags & NGX_USE_AIO_EVENT) {
        /* the posted aio operation may currupt a shadow buffer */
        p->single_buf = 1;
    }

    /* TODO: p->free_bufs = 0 if use ngx_create_chain_of_bufs() */
    p->free_bufs = 1;

    /*
     * event_pipe would do u->header_in.last += p->preread_size
     * as though these bytes were read
     */
    u->header_in.last = u->header_in.pos;

    if (u->conf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data may interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        p->cyclic_temp_file = 1;
        r->connection->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    p->read_timeout = u->conf->read_timeout;
    p->send_timeout = clcf->send_timeout;
    p->send_lowat = clcf->send_lowat;

    u->peer.connection->read->event_handler = ngx_http_upstream_process_body;
    r->connection->write->event_handler = ngx_http_upstream_process_body;

    ngx_http_upstream_process_body(u->peer.connection->read);
}


static void ngx_http_upstream_process_body(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;
    ngx_event_pipe_t     *p;

    c = ev->data;
    r = c->data;
    u = r->upstream;

    if (ev->write) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream process downstream");
        c->log->action = "sending to client";
    
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream process upstream");
        c->log->action = "reading upstream";
    }
    
    p = &u->pipe;

    if (ev->timedout) {
        if (ev->write) {
            p->downstream_error = 1;
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                          "client timed out");

        } else {
            p->upstream_error = 1; 
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

    } else {
        if (ngx_event_pipe(p, ev->write) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }
    
    if (u->peer.connection) {

#if (NGX_HTTP_FILE_CACHE)

        if (p->upstream_done && u->cachable) {
            if (ngx_http_cache_update(r) == NGX_ERROR) {
                ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

        } else if (p->upstream_eof && u->cachable) {

            /* TODO: check length & update cache */

            if (ngx_http_cache_update(r) == NGX_ERROR) {
                ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream exit: %p", p->out);
#if 0
            ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    if (p->downstream_error) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream downstream error");

        if (!u->cachable && u->peer.connection) {
            ngx_http_upstream_finalize_request(r, u, 0);
        }
    }
}


static void ngx_http_upstream_dummy_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http upstream dummy handler");
}


static void ngx_http_upstream_next(ngx_http_request_t *r,
                                   ngx_http_upstream_t *u,
                                   ngx_uint_t ft_type)
{
    ngx_uint_t  status;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xD", ft_type);

#if 0
    ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif

    if (ft_type != NGX_HTTP_UPSTREAM_FT_HTTP_404) {
        ngx_event_connect_peer_failed(&u->peer);
    }
    
    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }
    
    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) {
        status = 0;

    } else {
        switch(ft_type) {

        case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
            status = NGX_HTTP_GATEWAY_TIME_OUT;
            break;

        case NGX_HTTP_UPSTREAM_FT_HTTP_500:
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_HTTP_UPSTREAM_FT_HTTP_404:
            status = NGX_HTTP_NOT_FOUND;
            break;

        /*
         * NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING
         * never reach here
         */

        default:
            status = NGX_HTTP_BAD_GATEWAY;
        }
    }

    if (r->connection->write->eof) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    if (status) {
        u->state->status = status;

        if (u->peer.tries == 0 || !(u->conf->next_upstream & ft_type))
        {

#if (NGX_HTTP_CACHE)

            if (u->stale && (u->conf->use_stale & ft_type)) {
                ngx_http_upstream_finalize_request(r, u,
                                       ngx_http_send_cached_response(r));
                return;
            }

#endif

            ngx_http_upstream_finalize_request(r, u, status);
            return;
        }
    }

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        ngx_close_connection(u->peer.connection);
    }

#if 0
    if (u->conf->busy_lock && !u->busy_locked) {
        ngx_http_upstream_busy_lock(p);
        return;
    }
#endif

    ngx_http_upstream_connect(r, u);
}


static void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
                                               ngx_http_upstream_t *u,
                                               ngx_int_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    u->finalize_request(r, rc);

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->header_sent
        && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (u->saved_log_ctx) {
        r->connection->log->data = u->saved_log_ctx;
        r->connection->log->handler = u->saved_log_handler;
    }

    if (u->pipe.temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe.temp_file->file.fd);
    }

#if 0
    if (u->cache) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream cache fd: %d",
                       u->cache->ctx.file.fd);
    }
#endif

    if (u->pipe.temp_file) {
        r->file.fd = u->pipe.temp_file->file.fd;

#if 0
    } else if (u->cache) {
        r->file.fd = u->cache->ctx.file.fd;
#endif
    }

    r->connection->log->action = "sending to client";

    if (rc == 0 && r->main == NULL) {
        rc = ngx_http_send_last(r);
    }

    ngx_http_finalize_request(r, rc);
}


static size_t ngx_http_upstream_log_status_getlen(ngx_http_request_t *r,
                                                  uintptr_t data)
{
    if (r->upstream) {
        return r->upstream->states.nelts * (3 + 2);
    }

    return 1;
}


static u_char *ngx_http_upstream_log_status(ngx_http_request_t *r, u_char *buf,
                                            ngx_http_log_op_t *op)
{
    ngx_uint_t                  i;
    ngx_http_upstream_t        *u;
    ngx_http_upstream_state_t  *state;

    u = r->upstream;

    if (u == NULL) {
        *buf = '-';
        return buf + 1;
    }

    i = 0;
    state = u->states.elts;

    for ( ;; ) {
        if (state[i].status == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%ui", state[i].status);
        }

        if (++i == u->states.nelts) {
            return buf;
        }

        *buf++ = ',';
        *buf++ = ' ';
    }
}


u_char *ngx_http_upstream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_int_t               escape;
    ngx_str_t               uri;
    ngx_http_log_ctx_t     *ctx;
    ngx_http_request_t     *r;
    ngx_http_upstream_t    *u;
    ngx_peer_connection_t  *peer;

    ctx = log->data;
    r = ctx->request;
    u = r->upstream;
    peer = &u->peer;

    p = ngx_snprintf(buf, len,
                     " while %s, client: %V, URL: %V, upstream: %V%V%s%V",
                     log->action,
                     &r->connection->addr_text,
                     &r->unparsed_uri,
                     &u->schema,
                     &peer->peers->peer[peer->cur_peer].name,
                     peer->peers->peer[peer->cur_peer].uri_separator,
                     &u->uri);
    len -= p - buf;
    buf = p;

    if (r->quoted_uri) {
        escape = 2 * ngx_escape_uri(NULL, r->uri.data + u->location->len,
                                    r->uri.len - u->location->len,
                                    NGX_ESCAPE_URI);
    } else {
        escape = 0;
    }

    if (escape) {
        if (len >= r->uri.len - u->location->len + escape) {

            ngx_escape_uri(buf, r->uri.data + u->location->len,
                           r->uri.len - u->location->len, NGX_ESCAPE_URI);

            buf += r->uri.len - u->location->len + escape;

            if (r->args.len == 0) {
                return buf;
            }

            len -= r->uri.len - u->location->len + escape;

            return ngx_snprintf(buf, len, "?%V", &r->args);
        }

        p = ngx_palloc(r->pool, r->uri.len - u->location->len + escape);
        if (p == NULL) {
            return buf;
        }

        ngx_escape_uri(p, r->uri.data + u->location->len,
                       r->uri.len - u->location->len, NGX_ESCAPE_URI);

        uri.len = r->uri.len - u->location->len + escape;
        uri.data = p;

    } else {
        uri.len = r->uri.len - u->location->len;
        uri.data = r->uri.data + u->location->len;

    }

    return ngx_snprintf(buf, len, "%V%s%V", 
                        &uri, r->args.len ? "?" : "", &r->args);
}


static ngx_int_t ngx_http_upstream_add_log_formats(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_upstream_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->run = NULL;

    for (op = ngx_http_log_fmt_ops; op->run; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->run;
        }
    }

    op->run = (ngx_http_log_op_run_pt) ngx_http_upstream_log_fmt_ops;

    return NGX_OK;
}
