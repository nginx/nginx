
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


static void ngx_http_proxy_v2_session_cleanup(void *data);
static void ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev);
static void ngx_http_proxy_v2_session_write_handler(ngx_event_t *wev);
static ngx_int_t ngx_http_proxy_v2_session_dispatch(
    ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_wake_stream(
    ngx_http_proxy_v2_session_t *session);
static ssize_t ngx_http_proxy_v2_stream_recv(ngx_connection_t *c,
    u_char *buf, size_t size);
static ssize_t ngx_http_proxy_v2_stream_recv_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ssize_t ngx_http_proxy_v2_stream_send(ngx_connection_t *c,
    u_char *buf, size_t size);
static ngx_chain_t *ngx_http_proxy_v2_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_int_t ngx_http_proxy_v2_parse_goaway(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_window_update(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_settings(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_initial_window(
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, ssize_t update);
static void ngx_http_proxy_v2_update_initial_window(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ssize_t update);
static ngx_int_t ngx_http_proxy_v2_parse_ping(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_send_settings_ack(
    ngx_http_proxy_v2_session_t *session);
static ngx_int_t ngx_http_proxy_v2_send_ping_ack(
    ngx_http_proxy_v2_session_t *session);
static ngx_chain_t *ngx_http_proxy_v2_get_control_buf(
    ngx_http_proxy_v2_session_t *session);


ngx_int_t
ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session)
{
    ngx_connection_t    *c;
    ngx_pool_cleanup_t  *cln;

    c = pc->connection;

    if (pc->cached) {

        /* the session is stored in the real connection pool */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_proxy_v2_session_cleanup) {
                *session = cln->data;
                break;
            }
        }

        if (*session == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no session found for "
                          "keepalive http2 connection");
            return NGX_ERROR;
        }

        if (!ngx_http_proxy_v2_session_reusable(*session)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "keepalive http2 session is not reusable");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(c->pool,
                               sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_proxy_v2_session_cleanup;
    *session = cln->data;

    ngx_memzero(*session, sizeof(ngx_http_proxy_v2_session_t));

    (*session)->connection = c;
    ngx_rbtree_init(&(*session)->streams, &(*session)->streams_sentinel,
                    ngx_rbtree_insert_value);
    (*session)->output_tag =
                       (ngx_buf_tag_t) &ngx_http_proxy_v2_get_control_buf;
    (*session)->state = ngx_http_proxy_v2_st_start;
    (*session)->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    (*session)->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    (*session)->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    (*session)->last_stream_id = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_register_stream(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (stream->registered || stream->session != NULL) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 stream is already registered");
        return NGX_ERROR;
    }

    if (session->last_stream_id > NGX_HTTP_V2_MAX_WINDOW - 2) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 session has no available stream identifiers");
        return NGX_ERROR;
    }

    if (session->last_stream_id == 0) {
        session->last_stream_id = 1;

    } else {
        session->last_stream_id += 2;
    }

    stream->session = session;
    stream->id = session->last_stream_id;
    stream->node.key = stream->id;
    stream->send_window = session->init_window;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    stream->registered = 1;

    ngx_rbtree_insert(&session->streams, &stream->node);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_activate_stream(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (!stream->registered || stream->session != session) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "cannot activate unregistered http2 stream");
        return NGX_ERROR;
    }

    if (session->active_stream != NULL) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 session already has an active stream");
        return NGX_ERROR;
    }

    session->active_stream = stream;

    return NGX_OK;
}


void
ngx_http_proxy_v2_deactivate_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_t  *session;

    session = stream->session;

    if (session != NULL && session->active_stream == stream) {
        session->active_stream = NULL;
    }
}


void
ngx_http_proxy_v2_unregister_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_t  *session;

    session = stream->session;

    if (session == NULL || !stream->registered) {
        return;
    }

    ngx_http_proxy_v2_deactivate_stream(stream);
    ngx_rbtree_delete(&session->streams, &stream->node);

    stream->session = NULL;
    stream->registered = 0;
}


ngx_int_t
ngx_http_proxy_v2_create_stream_connection(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_upstream_t *u, size_t buffer_size)
{
    ngx_connection_t             *c, *sc;
    ngx_event_t                  *rev, *wev;
    ngx_http_proxy_v2_session_t  *session;

    if (stream->connection_created) {
        return NGX_OK;
    }

    session = stream->session;
    c = session->connection;

    if (session->buffer.start == NULL) {
        buffer_size = ngx_max(buffer_size,
                              2 * NGX_HTTP_V2_DEFAULT_FRAME_SIZE + 18);

        session->buffer.start = ngx_palloc(c->pool, buffer_size);
        if (session->buffer.start == NULL) {
            return NGX_ERROR;
        }

        session->buffer.pos = session->buffer.start;
        session->buffer.last = session->buffer.start;
        session->buffer.end = session->buffer.start + buffer_size;
        session->buffer.temporary = 1;
    }

    sc = ngx_pcalloc(stream->request->pool, sizeof(ngx_connection_t));
    rev = ngx_pcalloc(stream->request->pool, sizeof(ngx_event_t));
    wev = ngx_pcalloc(stream->request->pool, sizeof(ngx_event_t));
    if (sc == NULL || rev == NULL || wev == NULL) {
        return NGX_ERROR;
    }

    sc->data = stream->request;
    sc->read = rev;
    sc->write = wev;
    sc->fd = (ngx_socket_t) -1;
    sc->recv = ngx_http_proxy_v2_stream_recv;
    sc->recv_chain = ngx_http_proxy_v2_stream_recv_chain;
    sc->send = ngx_http_proxy_v2_stream_send;
    sc->send_chain = ngx_http_proxy_v2_stream_send_chain;
    sc->log = c->log;
    sc->pool = stream->request->pool;
    sc->type = c->type;
    sc->sockaddr = c->sockaddr;
    sc->socklen = c->socklen;
    sc->addr_text = c->addr_text;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;
    sc->buffered = c->buffered;
#if (NGX_SSL)
    sc->ssl = c->ssl;
#endif
    rev->data = sc;
    rev->handler = c->read->handler;
    rev->log = c->read->log;
    rev->active = 1;

    wev->data = sc;
    wev->handler = c->write->handler;
    wev->log = c->write->log;
    wev->write = 1;
    wev->active = 1;
    wev->ready = c->write->ready;

    stream->connection = sc;
    stream->read = rev;
    stream->write = wev;
    stream->connection_created = 1;

    session->connection_data = c->data;
    session->read_handler = c->read->handler;
    session->write_handler = c->write->handler;

    c->read->handler = ngx_http_proxy_v2_session_read_handler;
    c->write->handler = ngx_http_proxy_v2_session_write_handler;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u->peer.connection = sc;
    if (u->pipe) {
        u->pipe->upstream = sc;
    }

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    ngx_add_timer(c->read, u->conf->read_timeout);

    return NGX_OK;
}


void
ngx_http_proxy_v2_restore_connection(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_upstream_t *u)
{
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *session;

    if (!stream->connection_created) {
        return;
    }

    session = stream->session;
    c = session->connection;

    if (stream->read->posted) {
        ngx_delete_posted_event(stream->read);
    }

    if (stream->write->posted) {
        ngx_delete_posted_event(stream->write);
    }

    if (stream->read->timer_set) {
        ngx_del_timer(stream->read);
    }

    if (stream->write->timer_set) {
        ngx_del_timer(stream->write);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->data = session->connection_data;

#if (NGX_SSL)
    if (c->ssl && c->ssl->saved_read_handler
        == ngx_http_proxy_v2_session_read_handler)
    {
        c->ssl->saved_read_handler = session->read_handler;

    } else
#endif
    {
        c->read->handler = session->read_handler;
    }

#if (NGX_SSL)
    if (c->ssl && c->ssl->saved_write_handler
        == ngx_http_proxy_v2_session_write_handler)
    {
        c->ssl->saved_write_handler = session->write_handler;

    } else
#endif
    {
        c->write->handler = session->write_handler;
    }

    u->peer.connection = c;
    if (u->pipe) {
        u->pipe->upstream = c;
    }

    stream->connection_created = 0;
    stream->connection = NULL;
    stream->read = NULL;
    stream->write = NULL;

    ngx_http_proxy_v2_unregister_stream(stream);
}


ngx_uint_t
ngx_http_proxy_v2_session_reusable(ngx_http_proxy_v2_session_t *session)
{
    if (session->stream_frame
        && session->frame_sent == sizeof(session->frame_header)
        && session->frame_rest == 0
        && session->state == ngx_http_proxy_v2_st_start)
    {
        session->stream_frame = 0;
        session->frame_validated = 0;
        session->frame_sent = 0;
    }

    return session->out == NULL
           && session->busy == NULL
           && !session->stream_frame
           && session->active_stream == NULL
           && session->streams.root == session->streams.sentinel
           && session->buffer.pos == session->buffer.last
           && session->state == ngx_http_proxy_v2_st_start
           && session->rest == 0
           && !session->frame_validated
           && !session->goaway
           && !session->eof
           && !session->error_state
           && !session->connection->read->eof
           && !session->connection->read->error
           && !session->connection->read->timedout
           && !session->connection->write->error
           && !session->connection->write->timedout
           && !session->connection->buffered
#if (NGX_SSL)
           && (session->connection->ssl == NULL
               || (session->connection->ssl->saved_read_handler == NULL
                   && session->connection->ssl->saved_write_handler == NULL))
#endif
           ;
}


static void
ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev)
{
    ssize_t                       n;
    ngx_uint_t                    again;
    ngx_buf_t                    *b;
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_session_t  *session;
    ngx_http_proxy_v2_stream_t   *stream;

    c = rev->data;
    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return;
    }

    session = stream->session;
    b = &session->buffer;

    if (session->active_stream == NULL) {
        return;
    }

    if (rev->timedout) {
        session->error_state = 1;
        if (session->active_stream) {
            session->active_stream->read->timedout = 1;
        }
        ngx_http_proxy_v2_wake_stream(session);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for ( ;; ) {
        if (b->pos != b->start && b->pos != b->last) {
            b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;

        } else if (b->pos == b->last) {
            b->pos = b->start;
            b->last = b->start;
        }

        again = 0;

        while (b->last < b->end) {
            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_AGAIN) {
                again = 1;
                break;
            }

            if (n == NGX_ERROR) {
                session->error_state = 1;
                break;
            }

            if (n == 0) {
                session->eof = 1;
                break;
            }

            b->last += n;
        }

        if (ngx_http_proxy_v2_session_dispatch(session) != NGX_OK) {
            session->error_state = 1;
        }

        if (session->stream_frame || session->eof || session->error_state
            || again || !rev->ready)
        {
            break;
        }

        if (b->last == b->end && b->pos == b->start) {
            session->error_state = 1;
            break;
        }
    }

    ngx_http_proxy_v2_wake_stream(session);

    if (!session->eof && !session->error_state) {
        ngx_add_timer(rev, session->active_stream->request->upstream->conf
                                                   ->read_timeout);
    }
}


static void
ngx_http_proxy_v2_session_write_handler(ngx_event_t *wev)
{
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_stream_t   *active;
    ngx_http_proxy_v2_session_t  *session;
    ngx_http_proxy_v2_stream_t   *stream;

    c = wev->data;
    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return;
    }

    session = stream->session;
    u = r->upstream;

    r->main->count++;

    u->peer.connection = c;
    session->write_handler(wev);

    active = ngx_http_proxy_v2_get_stream(r);

    if (active == stream && stream->session == session
        && c->write->handler == ngx_http_proxy_v2_session_write_handler
        && u->peer.connection == c && stream->connection_created)
    {
        u->peer.connection = stream->connection;
        stream->write->ready = c->write->ready;
        stream->connection->buffered = c->buffered;
    }

    ngx_http_finalize_request(r, NGX_DONE);
}


static ngx_int_t
ngx_http_proxy_v2_session_dispatch(ngx_http_proxy_v2_session_t *session)
{
    ngx_int_t  rc;
    ngx_buf_t *b;

    b = &session->buffer;

    for ( ;; ) {
        if (session->stream_frame) {
            return NGX_OK;
        }

        if (session->state < ngx_http_proxy_v2_st_payload) {
            rc = ngx_http_proxy_v2_parse_frame(session, b);
            if (rc == NGX_AGAIN) {
                return NGX_OK;
            }
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        rc = ngx_http_proxy_v2_process_control_frame(session, b);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            continue;
        }

        session->frame_header[0] = (u_char) ((session->rest >> 16) & 0xff);
        session->frame_header[1] = (u_char) ((session->rest >> 8) & 0xff);
        session->frame_header[2] = (u_char) (session->rest & 0xff);
        session->frame_header[3] = session->type;
        session->frame_header[4] = session->flags;
        session->frame_header[5] =
                              (u_char) ((session->stream_id >> 24) & 0x7f);
        session->frame_header[6] =
                              (u_char) ((session->stream_id >> 16) & 0xff);
        session->frame_header[7] =
                              (u_char) ((session->stream_id >> 8) & 0xff);
        session->frame_header[8] = (u_char) (session->stream_id & 0xff);
        session->frame_sent = 0;
        session->frame_rest = session->rest;
        session->frame_validated = 1;
        session->stream_frame = 1;
        session->state = ngx_http_proxy_v2_st_start;

        return NGX_OK;
    }
}


static void
ngx_http_proxy_v2_wake_stream(ngx_http_proxy_v2_session_t *session)
{
    ngx_event_t  *rev;

    if (session->active_stream == NULL
        || !session->active_stream->connection_created)
    {
        return;
    }

    rev = session->active_stream->read;

    if (session->stream_frame || session->eof || session->error_state) {
        rev->ready = 1;
        rev->eof = session->eof;
        rev->error = session->error_state;
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static ssize_t
ngx_http_proxy_v2_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    size_t                         n, total;
    ngx_buf_t                     *b;
    ngx_http_request_t            *r;
    ngx_http_proxy_v2_session_t   *session;
    ngx_http_proxy_v2_stream_t    *stream;

    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return NGX_ERROR;
    }
    session = stream->session;
    b = &session->buffer;

    if (session->stream_frame && session->frame_rest == 0
        && session->frame_sent == sizeof(session->frame_header)
        && session->state == ngx_http_proxy_v2_st_start)
    {
        session->frame_validated = 0;
        session->stream_frame = 0;
        session->frame_sent = 0;
        session->frame_rest = 0;
        if (ngx_http_proxy_v2_session_dispatch(session) != NGX_OK) {
            session->error_state = 1;
        }

        ngx_http_proxy_v2_wake_stream(session);

        if (!session->stream_frame && !session->eof && !session->error_state
            && session->connection->read->ready)
        {
            ngx_post_event(session->connection->read, &ngx_posted_events);
        }
    }

    if (session->error_state && !session->stream_frame) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    total = 0;

    if (session->stream_frame
        && session->frame_sent < sizeof(session->frame_header))
    {
        n = ngx_min(size, sizeof(session->frame_header) - session->frame_sent);
        ngx_memcpy(buf, session->frame_header + session->frame_sent, n);
        session->frame_sent += n;
        buf += n;
        size -= n;
        total += n;
    }

    if (size && session->stream_frame && session->frame_rest && b->pos < b->last)
    {
        n = ngx_min(size, session->frame_rest);
        n = ngx_min(n, (size_t) (b->last - b->pos));
        ngx_memcpy(buf, b->pos, n);
        b->pos += n;
        session->frame_rest -= n;
        total += n;
    }

    if (total) {
        return total;
    }

    c->read->ready = 0;

    if (session->eof) {
        c->read->eof = 1;
        return 0;
    }

    return NGX_AGAIN;
}


static ssize_t
ngx_http_proxy_v2_stream_recv_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    size_t    size;
    ssize_t   n, total;
    ngx_buf_t *b;

    total = 0;

    for ( /* void */ ; in; in = in->next) {
        b = in->buf;
        size = b->end - b->last;

        if (limit > 0 && total >= limit) {
            break;
        }

        if (limit > 0 && size > (size_t) (limit - total)) {
            size = limit - total;
        }

        if (size == 0) {
            break;
        }

        n = ngx_http_proxy_v2_stream_recv(c, b->last, size);
        if (n == NGX_AGAIN || n == NGX_ERROR || n == 0) {
            return total ? total : n;
        }

        total += n;

        if ((size_t) n < size || (limit > 0 && total == limit)) {
            break;
        }
    }

    return total;
}


static ssize_t
ngx_http_proxy_v2_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                     n;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_stream_t  *stream;

    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return NGX_ERROR;
    }

    n = stream->session->connection->send(stream->session->connection,
                                          buf, size);
    c->buffered = stream->session->connection->buffered;

    return n;
}


static ngx_chain_t *
ngx_http_proxy_v2_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    ngx_chain_t                 *cl;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_stream_t  *stream;

    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl = stream->session->connection->send_chain(
                                      stream->session->connection, in, limit);
    c->buffered = stream->session->connection->buffered;

    return cl;
}


ngx_int_t
ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char                     ch, *p;
    ngx_http_proxy_v2_state_e  state;

    state = session->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                       "http proxy frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case ngx_http_proxy_v2_st_start:
            session->rest = ch << 16;
            state = ngx_http_proxy_v2_st_length_2;
            break;

        case ngx_http_proxy_v2_st_length_2:
            session->rest |= ch << 8;
            state = ngx_http_proxy_v2_st_length_3;
            break;

        case ngx_http_proxy_v2_st_length_3:
            session->rest |= ch;

            if (!session->frame_validated
                && session->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE)
            {
                ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              session->rest);
                return NGX_ERROR;
            }

            state = ngx_http_proxy_v2_st_type;
            break;

        case ngx_http_proxy_v2_st_type:
            session->type = ch;
            state = ngx_http_proxy_v2_st_flags;
            break;

        case ngx_http_proxy_v2_st_flags:
            session->flags = ch;
            state = ngx_http_proxy_v2_st_stream_id;
            break;

        case ngx_http_proxy_v2_st_stream_id:
            session->stream_id = (ch & 0x7f) << 24;
            state = ngx_http_proxy_v2_st_stream_id_2;
            break;

        case ngx_http_proxy_v2_st_stream_id_2:
            session->stream_id |= ch << 16;
            state = ngx_http_proxy_v2_st_stream_id_3;
            break;

        case ngx_http_proxy_v2_st_stream_id_3:
            session->stream_id |= ch << 8;
            state = ngx_http_proxy_v2_st_stream_id_4;
            break;

        case ngx_http_proxy_v2_st_stream_id_4:
            session->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           session->type, session->rest, session->flags,
                           session->stream_id);

            b->pos = p + 1;

            session->state = ngx_http_proxy_v2_st_payload;
            session->frame_state = 0;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
        case ngx_http_proxy_v2_st_padding:
            break;
        }
    }

    b->pos = p;
    session->state = state;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_proxy_v2_process_control_frame(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b)
{
    ngx_int_t  rc;

    switch (session->type) {

    case NGX_HTTP_V2_GOAWAY_FRAME:
        rc = ngx_http_proxy_v2_parse_goaway(session, b);

        if (rc != NGX_OK) {
            return rc;
        }

        session->goaway = 1;

        if (session->active_stream != NULL
            && session->goaway_stream_id < session->active_stream->id)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent goaway with error %ui",
                          session->error);
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:
        rc = ngx_http_proxy_v2_parse_window_update(session, b);

        if (rc == NGX_OK && session->active_stream->in) {
            ngx_post_event(session->connection->write, &ngx_posted_events);
        }

        return rc;

    case NGX_HTTP_V2_SETTINGS_FRAME:
        rc = ngx_http_proxy_v2_parse_settings(session, b);

        if (rc == NGX_OK && session->active_stream->in) {
            ngx_post_event(session->connection->write, &ngx_posted_events);
        }

        return rc;

    case NGX_HTTP_V2_PING_FRAME:
        rc = ngx_http_proxy_v2_parse_ping(session, b);

        if (rc == NGX_OK) {
            ngx_post_event(session->connection->write, &ngx_posted_events);
        }

        return rc;

    case NGX_HTTP_V2_PUSH_PROMISE_FRAME:
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "upstream sent unexpected push promise frame");
        return NGX_ERROR;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_DATA_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:
    case NGX_HTTP_V2_RST_STREAM_FRAME:
        return NGX_DECLINED;
    }

    if (session->stream_id == 0) {
        return ngx_http_proxy_v2_skip_frame(session, b);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_v2_parse_goaway(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start) {
        if (session->stream_id) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui", session->stream_id);
            return NGX_ERROR;
        }

        if (session->rest < 8) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz", session->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        switch (state) {
        case sw_start:
            session->goaway_stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;
        case sw_last_stream_id_2:
            session->goaway_stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;
        case sw_last_stream_id_3:
            session->goaway_stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;
        case sw_last_stream_id_4:
            session->goaway_stream_id |= ch;
            state = sw_error;
            break;
        case sw_error:
            session->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;
        case sw_error_2:
            session->error |= ch << 16;
            state = sw_error_3;
            break;
        case sw_error_3:
            session->error |= ch << 8;
            state = sw_error_4;
            break;
        case sw_error_4:
            session->error |= ch;
            state = sw_debug;
            break;
        case sw_debug:
            break;
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   session->error, session->goaway_stream_id);

    session->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_window_update(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum { sw_start = 0, sw_size_2, sw_size_3, sw_size_4 } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start && session->rest != 4) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "upstream sent window update frame "
                      "with invalid length: %uz", session->rest);
        return NGX_ERROR;
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        switch (state) {
        case sw_start:
            session->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;
        case sw_size_2:
            session->window_update |= ch << 16;
            state = sw_size_3;
            break;
        case sw_size_3:
            session->window_update |= ch << 8;
            state = sw_size_4;
            break;
        case sw_size_4:
            session->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    session->state = ngx_http_proxy_v2_st_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy window update: %ui", session->window_update);

    if (session->window_update == 0) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "upstream sent zero window update");
        return NGX_ERROR;
    }

    if (session->stream_id) {
        if (session->active_stream == NULL
            || session->stream_id != session->active_stream->id)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent window update frame "
                          "for unknown stream %ui", session->stream_id);
            return NGX_ERROR;
        }

        if (session->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                     - session->active_stream->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        session->active_stream->send_window += session->window_update;

    } else {
        if (session->window_update > NGX_HTTP_V2_MAX_WINDOW
                                     - session->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        session->send_window += session->window_update;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_settings(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char   ch, *p, *last;
    ssize_t  window_update;
    enum {
        sw_start = 0, sw_id, sw_id_2, sw_value, sw_value_2, sw_value_3,
        sw_value_4
    } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start) {
        if (session->stream_id) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui", session->stream_id);
            return NGX_ERROR;
        }

        if (session->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy settings ack");

            if (session->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              session->rest);
                return NGX_ERROR;
            }

            session->state = ngx_http_proxy_v2_st_start;
            return NGX_OK;
        }

        if (session->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz", session->rest);
            return NGX_ERROR;
        }

        if (session->free == NULL && session->settings++ > 1000) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too many settings frames");
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        switch (state) {
        case sw_start:
        case sw_id:
            session->setting_id = ch << 8;
            state = sw_id_2;
            break;
        case sw_id_2:
            session->setting_id |= ch;
            state = sw_value;
            break;
        case sw_value:
            session->setting_value = (ngx_uint_t) ch << 24;
            state = sw_value_2;
            break;
        case sw_value_2:
            session->setting_value |= ch << 16;
            state = sw_value_3;
            break;
        case sw_value_3:
            session->setting_value |= ch << 8;
            state = sw_value_4;
            break;
        case sw_value_4:
            session->setting_value |= ch;
            state = sw_id;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy setting: %ui %ui",
                           session->setting_id, session->setting_value);

            if (session->setting_id == 0x04) {
                if (session->setting_value > NGX_HTTP_V2_MAX_WINDOW) {
                    ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                                  "upstream sent settings frame with too "
                                  "large initial window size: %ui",
                                  session->setting_value);
                    return NGX_ERROR;
                }

                window_update = session->setting_value - session->init_window;

                if (ngx_http_proxy_v2_validate_initial_window(
                        session->streams.root, session->streams.sentinel,
                        window_update)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                                  "upstream sent settings frame with too "
                                  "large initial window size: %ui",
                                  session->setting_value);
                    return NGX_ERROR;
                }

                session->init_window = session->setting_value;
                ngx_http_proxy_v2_update_initial_window(
                    session->streams.root, session->streams.sentinel,
                    window_update);
            }
            break;
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    session->state = ngx_http_proxy_v2_st_start;

    return ngx_http_proxy_v2_send_settings_ack(session);
}


static ngx_int_t
ngx_http_proxy_v2_validate_initial_window(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ssize_t update)
{
    ngx_http_proxy_v2_stream_t  *stream;

    if (node == sentinel) {
        return NGX_OK;
    }

    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

    if (stream->send_window > 0
        && update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW - stream->send_window)
    {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_v2_validate_initial_window(node->left, sentinel, update)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return ngx_http_proxy_v2_validate_initial_window(node->right, sentinel,
                                                      update);
}


static void
ngx_http_proxy_v2_update_initial_window(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ssize_t update)
{
    ngx_http_proxy_v2_stream_t  *stream;

    if (node == sentinel) {
        return;
    }

    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
    stream->send_window += update;

    ngx_http_proxy_v2_update_initial_window(node->left, sentinel, update);
    ngx_http_proxy_v2_update_initial_window(node->right, sentinel, update);
}


static ngx_int_t
ngx_http_proxy_v2_parse_ping(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0, sw_data_2, sw_data_3, sw_data_4, sw_data_5, sw_data_6,
        sw_data_7, sw_data_8
    } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start) {
        if (session->stream_id) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui", session->stream_id);
            return NGX_ERROR;
        }

        if (session->rest != 8) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz", session->rest);
            return NGX_ERROR;
        }

        if (session->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent ping frame with ack flag");
            return NGX_ERROR;
        }

        if (session->free == NULL && session->pings++ > 1000) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too many ping frames");
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        if (state < sw_data_8) {
            session->ping_data[state] = ch;
            state++;
        } else {
            session->ping_data[7] = ch;
            state = sw_start;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy ping");
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    session->state = ngx_http_proxy_v2_st_start;

    return ngx_http_proxy_v2_send_ping_ack(session);
}


static ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) session->rest) {
        session->rest -= b->last - b->pos;
        b->pos = b->last;
        return NGX_AGAIN;
    }

    b->pos += session->rest;
    session->rest = 0;
    session->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_settings_ack(ngx_http_proxy_v2_session_t *session)
{
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send settings ack");

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->type = NGX_HTTP_V2_SETTINGS_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;

    *ll = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_ping_ack(ngx_http_proxy_v2_session_t *session)
{
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send ping ack");

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 8;
    f->type = NGX_HTTP_V2_PING_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;

    cl->buf->last = ngx_copy(cl->buf->last, session->ping_data, 8);
    *ll = cl;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_send_connection_window_update(
    ngx_http_proxy_v2_session_t *session)
{
    size_t                      n;
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send connection window update: %uz",
                   session->recv_window);

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;

    n = NGX_HTTP_V2_MAX_WINDOW - session->recv_window;
    session->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_control_buf(ngx_http_proxy_v2_session_t *session)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    ngx_pool_t   *pool;

    pool = session->connection->pool;

    cl = ngx_chain_get_free_buf(pool, &session->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {
        start = ngx_palloc(pool, 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }
    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8;
    b->tag = session->output_tag;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static void
ngx_http_proxy_v2_session_cleanup(void *data)
{
    ngx_rbtree_node_t            *node;
    ngx_http_proxy_v2_session_t  *session = data;
    ngx_http_proxy_v2_stream_t   *stream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy session cleanup");

    while (session->streams.root != session->streams.sentinel) {
        node = session->streams.root;
        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

        ngx_rbtree_delete(&session->streams, node);
        stream->session = NULL;
        stream->registered = 0;
    }

    if (session->active_stream != NULL) {
        ngx_log_error(NGX_LOG_ALERT, session->connection->log, 0,
                      "http2 session cleanup with an active stream");
        session->active_stream = NULL;
    }

    return;
}
