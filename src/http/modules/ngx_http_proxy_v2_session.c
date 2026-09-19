
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


static void ngx_http_proxy_v2_session_cleanup(void *data);
static ngx_int_t ngx_http_proxy_v2_parse_goaway(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_window_update(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_settings(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
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
ngx_http_proxy_v2_attach_stream(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (session->stream != NULL) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 session already has an active stream");
        return NGX_ERROR;
    }

    if (session->last_stream_id == 0) {
        session->last_stream_id = 1;

    } else {
        session->last_stream_id += 2;
    }

    stream->session = session;
    stream->id = session->last_stream_id;
    stream->send_window = session->init_window;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    session->stream = stream;

    return NGX_OK;
}


void
ngx_http_proxy_v2_detach_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_t  *session;

    session = stream->session;

    if (session != NULL && session->stream == stream) {
        session->stream = NULL;
    }

    stream->session = NULL;
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

            if (session->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
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

        if (session->stream != NULL
            && session->goaway_stream_id < session->stream->id)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent goaway with error %ui",
                          session->error);
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:
        rc = ngx_http_proxy_v2_parse_window_update(session, b);

        if (rc == NGX_OK && session->stream->in) {
            ngx_post_event(session->connection->write, &ngx_posted_events);
        }

        return rc;

    case NGX_HTTP_V2_SETTINGS_FRAME:
        rc = ngx_http_proxy_v2_parse_settings(session, b);

        if (rc == NGX_OK && session->stream->in) {
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
        if (session->stream == NULL
            || session->stream_id != session->stream->id)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent window update frame "
                          "for unknown stream %ui", session->stream_id);
            return NGX_ERROR;
        }

        if (session->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                     - session->stream->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        session->stream->send_window += session->window_update;

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
                session->init_window = session->setting_value;

                if (session->stream->send_window > 0
                    && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                       - session->stream->send_window)
                {
                    ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                                  "upstream sent settings frame with too "
                                  "large initial window size: %ui",
                                  session->setting_value);
                    return NGX_ERROR;
                }

                session->stream->send_window += window_update;
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
#if 0
    ngx_http_proxy_v2_session_t  *session = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy session cleanup");
#endif
    return;
}
