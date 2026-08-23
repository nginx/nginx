
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


#define NGX_HTTP_PROXY_V2_FRAME_BUFFER_SIZE                              \
    (NGX_HTTP_V2_FRAME_HEADER_SIZE + NGX_HTTP_V2_DEFAULT_FRAME_SIZE)


static void
ngx_http_proxy_v2_session_cleanup(void *data)
{
    return;
}


ngx_http_proxy_v2_stream_t *
ngx_http_proxy_v2_stream_create(ngx_pool_t *pool, ngx_http_request_t *r)
{
    ngx_http_proxy_v2_stream_t  *stream;

    stream = ngx_palloc(pool, sizeof(ngx_http_proxy_v2_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    stream->request = r;
    stream->session = NULL;
    stream->connection = NULL;

    ngx_memzero(&stream->node, sizeof(ngx_rbtree_node_t));

    stream->id = 0;
    stream->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    stream->frames = NULL;
    stream->recv_frame = NULL;
    stream->free_frames = NULL;
    stream->last_frame = &stream->frames;

    stream->goaway = 0;
    stream->unprocessed = 0;
    stream->registered = 0;

    return stream;
}


void
ngx_http_proxy_v2_stream_reset_frames(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_in_frame_t  *frame;

    while (stream->frames) {
        frame = stream->frames;
        stream->frames = frame->next;
        frame->next = stream->free_frames;
        stream->free_frames = frame;
    }

    stream->recv_frame = NULL;
    stream->last_frame = &stream->frames;
}


ngx_http_proxy_v2_in_frame_t *
ngx_http_proxy_v2_stream_peek_frame(ngx_http_proxy_v2_stream_t *stream)
{
    return stream->frames;
}


ngx_http_proxy_v2_in_frame_t *
ngx_http_proxy_v2_stream_dequeue_frame(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_in_frame_t  *frame;

    frame = stream->frames;

    if (frame) {
        stream->frames = frame->next;

        if (stream->recv_frame == frame) {
            stream->recv_frame = frame->next;
        }

        if (stream->frames == NULL) {
            stream->last_frame = &stream->frames;
        }
    }

    return frame;
}


void
ngx_http_proxy_v2_stream_free_frame(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_proxy_v2_in_frame_t *frame)
{
    frame->next = stream->free_frames;
    stream->free_frames = frame;
}


void
ngx_http_proxy_v2_session_init(ngx_http_proxy_v2_session_t *s)
{
    s->frame_parse.state = 0;

    s->connection = NULL;
    s->stream = NULL;
    s->input = NULL;

    ngx_rbtree_init(&s->streams, &s->streams_sentinel,
                    ngx_rbtree_insert_value);

    s->output_pos = s->output;
    s->output_last = s->output;

    s->frame_size = 0;

    s->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    s->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    s->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    s->last_stream_id = 1;
    s->peer_last_stream_id = 0;
    s->goaway_error = 0;
    s->connection_error = 0;

    s->frame_header = 0;
    s->frame_ready = 0;
    s->frame_error = 0;
    s->output_blocked = 0;
    s->goaway = 0;
}


ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_session_create(ngx_connection_t *c)
{
    ngx_pool_cleanup_t            *cln;
    ngx_http_proxy_v2_session_t   *s;

    cln = ngx_pool_cleanup_add(c->pool,
                               sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_proxy_v2_session_cleanup;
    s = cln->data;

    ngx_http_proxy_v2_session_init(s);

    return s;
}


ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_session_get(ngx_connection_t *c)
{
    ngx_pool_cleanup_t  *cln;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_proxy_v2_session_cleanup) {
            return cln->data;
        }
    }

    return NULL;
}


ngx_int_t
ngx_http_proxy_v2_session_register_stream(ngx_http_proxy_v2_session_t *s,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (stream->registered
        || stream->id == 0
        || ngx_http_proxy_v2_session_find_stream(s, stream->id) != NULL)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&stream->node, sizeof(ngx_rbtree_node_t));
    stream->node.key = stream->id;

    ngx_rbtree_insert(&s->streams, &stream->node);

    stream->session = s;
    stream->registered = 1;

    return NGX_OK;
}


ngx_http_proxy_v2_stream_t *
ngx_http_proxy_v2_session_find_stream(ngx_http_proxy_v2_session_t *s,
    ngx_uint_t stream_id)
{
    ngx_rbtree_node_t         *node, *sentinel;
    ngx_http_proxy_v2_stream_t *stream;

    node = s->streams.root;
    sentinel = s->streams.sentinel;

    while (node != sentinel) {
        if (stream_id < node->key) {
            node = node->left;
            continue;
        }

        if (stream_id > node->key) {
            node = node->right;
            continue;
        }

        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

        return stream;
    }

    return NULL;
}


void
ngx_http_proxy_v2_session_unregister_stream(ngx_http_proxy_v2_session_t *s,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (!stream->registered || stream->session != s) {
        return;
    }

    ngx_rbtree_delete(&s->streams, &stream->node);

    stream->registered = 0;
    stream->session = NULL;
}


ngx_int_t
ngx_http_proxy_v2_session_attach(ngx_http_proxy_v2_session_t *s,
    ngx_connection_t *c, ngx_http_proxy_v2_stream_t *stream)
{
    if (ngx_http_proxy_v2_session_register_stream(s, stream) != NGX_OK) {
        return NGX_ERROR;
    }

    s->connection = c;
    s->stream = stream;

    return NGX_OK;
}


void
ngx_http_proxy_v2_session_detach(ngx_http_proxy_v2_session_t *s,
    ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_unregister_stream(s, stream);

    if (s->stream == stream) {
        s->stream = NULL;
    }
}


ngx_int_t
ngx_http_proxy_v2_session_dispatch_stream_frame(
    ngx_http_proxy_v2_session_t *s)
{
    ngx_buf_t                     *b;
    ngx_connection_t              *sc;
    ngx_event_t                   *rev;
    size_t                         size;
    u_char                        *p;
    ngx_http_proxy_v2_stream_t    *target;
    ngx_http_proxy_v2_in_frame_t  *frame;

    b = s->input;

    target = ngx_http_proxy_v2_session_find_stream(s,
                                                   s->frame_parse.stream_id);
    if (target == NULL) {
        return NGX_ERROR;
    }

    sc = target->connection;

    if (sc == NULL) {
        return NGX_ERROR;
    }

    size = b->last - b->start;

    if (target->free_frames) {
        frame = target->free_frames;
        target->free_frames = frame->next;

    } else {
        frame = ngx_palloc(target->request->pool,
                           sizeof(ngx_http_proxy_v2_in_frame_t));
        if (frame == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(&frame->buffer, sizeof(ngx_buf_t));
    }

    if (frame->buffer.start == NULL
        || (size_t) (frame->buffer.end - frame->buffer.start) < size)
    {
        p = ngx_palloc(target->request->pool, size);
        if (p == NULL) {
            frame->next = target->free_frames;
            target->free_frames = frame;
            return NGX_ERROR;
        }

        frame->buffer.start = p;
        frame->buffer.end = p + size;
    }

    frame->parse = s->frame_parse;
    frame->buffer.pos = frame->buffer.start;
    frame->buffer.last = ngx_cpymem(frame->buffer.start, b->start, size);
    frame->buffer.temporary = 1;
    frame->error = s->frame_error;
    frame->parsed = 0;
    frame->next = NULL;

    *target->last_frame = frame;
    target->last_frame = &frame->next;

    if (target->recv_frame == NULL) {
        target->recv_frame = frame;
    }

    ngx_http_proxy_v2_session_frame_done(s);

    sc->read->ready = 1;
    sc->read->eof = 0;
    sc->read->error = 0;
    sc->read->timedout = 0;

    rev = s->connection->read;

    if (rev->timer_set && !rev->timedout) {
        ngx_del_timer(rev);
        ngx_add_timer(sc->read,
                      target->request->upstream->conf->read_timeout);
    }

    if (!sc->read->posted) {
        ngx_post_event(sc->read, &ngx_posted_events);
    }

    return NGX_OK;
}


void
ngx_http_proxy_v2_session_frame_done(ngx_http_proxy_v2_session_t *s)
{
    ngx_buf_t  *b;

    b = s->input;

    b->pos = b->start;
    b->last = b->start;

    s->frame_size = 0;
    s->frame_header = 0;
    s->frame_ready = 0;
    s->frame_error = 0;
}


ngx_int_t
ngx_http_proxy_v2_session_process_ping(ngx_http_proxy_v2_session_t *s)
{
    u_char  data[NGX_HTTP_PROXY_V2_PING_SIZE];
    u_char *p;

    if (ngx_http_proxy_v2_frame_parse_ping(&s->frame_parse, s->input, data)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid ping frame");
        return NGX_ERROR;
    }

    if (s->frame_parse.flags & NGX_HTTP_V2_ACK_FLAG) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "http proxy ping ack");

        ngx_http_proxy_v2_session_frame_done(s);
        return NGX_OK;
    }

    if (s->output_pos != s->output_last) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "http proxy session output is busy");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy send ping ack");

    p = s->output;

    *p++ = 0;
    *p++ = 0;
    *p++ = NGX_HTTP_PROXY_V2_PING_SIZE;
    *p++ = NGX_HTTP_V2_PING_FRAME;
    *p++ = NGX_HTTP_V2_ACK_FLAG;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    p = ngx_cpymem(p, data, NGX_HTTP_PROXY_V2_PING_SIZE);

    s->output_pos = s->output;
    s->output_last = p;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_window_update(
    ngx_http_proxy_v2_session_t *s)
{
    ngx_uint_t   n;

    if (ngx_http_proxy_v2_frame_parse_window_update(&s->frame_parse, s->input,
                                                    &n)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid connection window update frame");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy connection window update: %ui", n);

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent zero window update");
        return NGX_ERROR;
    }

    if (n > NGX_HTTP_V2_MAX_WINDOW - s->send_window) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent too large connection window update");
        return NGX_ERROR;
    }

    s->send_window += n;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_settings(ngx_http_proxy_v2_session_t *s,
    ssize_t *window_update)
{
    u_char                        *p;
    ngx_http_proxy_v2_settings_t  settings;

    if (ngx_http_proxy_v2_frame_parse_settings(&s->frame_parse, s->input,
                                               &settings)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid settings frame");
        return NGX_ERROR;
    }

    *window_update = 0;

    if (settings.ack) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "http proxy settings ack");

        ngx_http_proxy_v2_session_frame_done(s);
        return NGX_OK;
    }

    if (settings.initial_window_set) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "http proxy initial stream window: %ui",
                       settings.initial_window);

        *window_update = (ssize_t) settings.initial_window
                         - (ssize_t) s->init_window;
        s->init_window = settings.initial_window;
    }

    if (s->output_pos != s->output_last) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "http proxy session output is busy");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy send settings ack");

    p = s->output;

    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = NGX_HTTP_V2_SETTINGS_FRAME;
    *p++ = NGX_HTTP_V2_ACK_FLAG;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    s->output_pos = s->output;
    s->output_last = p;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_goaway(ngx_http_proxy_v2_session_t *s)
{
    ngx_http_proxy_v2_goaway_t  goaway;

    if (ngx_http_proxy_v2_frame_parse_goaway(&s->frame_parse, s->input,
                                             &goaway)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid goaway frame");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   goaway.error, goaway.last_stream_id);

    s->peer_last_stream_id = goaway.last_stream_id;
    s->goaway_error = goaway.error;
    s->goaway = 1;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_connection_frame(
    ngx_http_proxy_v2_session_t *s)
{
    ngx_connection_t            *c;
    ngx_rbtree_node_t           *node;
    ngx_uint_t                   unprocessed;
    ssize_t                      window_update;
    ngx_http_proxy_v2_stream_t  *stream;

    c = s->connection;

    if (s->frame_error) {
        return NGX_DECLINED;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_GOAWAY_FRAME) {
        if (ngx_http_proxy_v2_session_process_goaway(s) != NGX_OK) {
            return NGX_ERROR;
        }

        unprocessed = 0;

        if (s->streams.root == s->streams.sentinel) {
            node = NULL;

        } else {
            node = ngx_rbtree_min(s->streams.root, s->streams.sentinel);
        }

        while (node) {
            stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

            stream->goaway = 1;
            stream->unprocessed = (stream->id > s->peer_last_stream_id);

            if (stream->unprocessed) {
                unprocessed = 1;
            }

            node = ngx_rbtree_next(&s->streams, node);
        }

        if (unprocessed) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "upstream sent goaway with error %ui",
                          s->goaway_error);

            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "upstream sent unexpected push promise frame");

        s->connection_error = NGX_HTTP_PROXY_V2_PROTOCOL_ERROR;

        return NGX_ERROR;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_PING_FRAME) {
        if (ngx_http_proxy_v2_session_process_ping(s) != NGX_OK) {
            return NGX_ERROR;
        }

        goto output;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME
        && s->frame_parse.stream_id == 0)
    {
        if (ngx_http_proxy_v2_session_process_window_update(s) != NGX_OK) {
            return NGX_ERROR;
        }

        if (!c->write->posted) {
            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_SETTINGS_FRAME) {
        if (ngx_http_proxy_v2_session_process_settings(s, &window_update)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (s->streams.root == s->streams.sentinel) {
            node = NULL;

        } else {
            node = ngx_rbtree_min(s->streams.root, s->streams.sentinel);
        }

        while (node) {
            stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

            if (stream->send_window > 0
                && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                   - stream->send_window)
            {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream sent settings frame "
                              "with too large initial window size");
                return NGX_ERROR;
            }

            node = ngx_rbtree_next(&s->streams, node);
        }

        if (s->streams.root == s->streams.sentinel) {
            node = NULL;

        } else {
            node = ngx_rbtree_min(s->streams.root, s->streams.sentinel);
        }

        while (node) {
            stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
            stream->send_window += window_update;
            node = ngx_rbtree_next(&s->streams, node);
        }

        goto output;
    }

    return NGX_DECLINED;

output:

    if (s->output_pos == s->output_last) {
        return NGX_OK;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!c->write->posted) {
        ngx_post_event(c->write, &ngx_posted_events);
    }

    return NGX_AGAIN;
}


static void
ngx_http_proxy_v2_session_wake_streams(ngx_http_proxy_v2_session_t *s,
    ngx_uint_t timedout)
{
    ngx_connection_t            *sc;
    ngx_rbtree_node_t           *node;
    ngx_http_proxy_v2_stream_t  *stream;

    if (s->streams.root == s->streams.sentinel) {
        return;
    }

    node = ngx_rbtree_min(s->streams.root, s->streams.sentinel);

    while (node) {
        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
        sc = stream->connection;

        if (sc) {
            sc->read->ready = 1;

            if (timedout) {
                sc->read->timedout = 1;

            } else {
                sc->read->error = 1;
            }

            if (!sc->read->posted) {
                ngx_post_event(sc->read, &ngx_posted_events);
            }
        }

        node = ngx_rbtree_next(&s->streams, node);
    }
}


static ngx_int_t
ngx_http_proxy_v2_session_read_frame(ngx_http_proxy_v2_session_t *s)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b, header;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = s->connection;
    b = s->input;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool,
                                NGX_HTTP_PROXY_V2_FRAME_BUFFER_SIZE);
        if (b == NULL) {
            return NGX_ERROR;
        }

        s->input = b;
    }

    for ( ;; ) {

        if (!s->frame_header
            && b->last - b->start == NGX_HTTP_V2_FRAME_HEADER_SIZE)
        {
            ngx_memcpy(&header, b, sizeof(ngx_buf_t));
            header.pos = header.start;

            rc = ngx_http_proxy_v2_frame_parse(&s->frame_parse, &header);

            if (rc == NGX_ERROR) {
                s->frame_parse.state = 0;
                s->frame_size = NGX_HTTP_V2_FRAME_HEADER_SIZE;
                s->frame_ready = 1;
                s->frame_error = 1;
                b->pos = b->start;
                return NGX_OK;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            s->frame_size = NGX_HTTP_V2_FRAME_HEADER_SIZE
                            + s->frame_parse.length;
            s->frame_header = 1;

            if ((size_t) (b->last - b->start) == s->frame_size) {
                s->frame_ready = 1;
                b->pos = b->start;
                return NGX_OK;
            }
        }

        size = (s->frame_header ? s->frame_size
                                : NGX_HTTP_V2_FRAME_HEADER_SIZE)
               - (b->last - b->start);

        n = c->recv(c, b->last, size);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        if (n == NGX_ERROR || n == 0) {
            return NGX_ERROR;
        }

        b->last += n;

        if (s->frame_header
            && (size_t) (b->last - b->start) == s->frame_size)
        {
            s->frame_ready = 1;
            b->pos = b->start;
            return NGX_OK;
        }
    }
}


void
ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev)
{
    ngx_int_t                    rc;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *s;

    c = rev->data;
    s = ngx_http_proxy_v2_session_get(c);

    if (s == NULL) {
        return;
    }

    if (rev->timedout) {
        ngx_http_proxy_v2_session_wake_streams(s, 1);
        return;
    }

    for ( ;; ) {
        rc = ngx_http_proxy_v2_session_read_frame(s);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_http_proxy_v2_session_wake_streams(s, 0);
            return;
        }

        rc = ngx_http_proxy_v2_session_process_connection_frame(s);

        if (rc == NGX_ERROR) {
            ngx_http_proxy_v2_session_wake_streams(s, 0);
            return;
        }

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_OK) {
            continue;
        }

        if (ngx_http_proxy_v2_session_dispatch_stream_frame(s) != NGX_OK) {
            ngx_http_proxy_v2_session_wake_streams(s, 0);
            return;
        }
    }
}


ngx_int_t
ngx_http_proxy_v2_session_send(ngx_http_proxy_v2_session_t *s)
{
    ssize_t  n;

    while (s->output_pos < s->output_last) {
        n = s->connection->send(s->connection, s->output_pos,
                                s->output_last - s->output_pos);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        s->output_pos += n;
    }

    s->output_pos = s->output;
    s->output_last = s->output;

    return NGX_OK;
}
