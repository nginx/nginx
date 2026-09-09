
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


static void ngx_http_proxy_v2_cleanup_session(void *data);


ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_create_session(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t           *cln;
    ngx_http_proxy_v2_session_t  *sess;

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_proxy_v2_cleanup_session;
    sess = cln->data;

    sess->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    sess->last_stream_id = 1;

    sess->header_state = 0;
    sess->ping_length = 0;
    sess->goaway_length = 0;
    sess->goaway = 0;

    return sess;
}


ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc)
{
    ngx_connection_t             *c;
    ngx_pool_cleanup_t           *cln;
    ngx_http_proxy_v2_session_t  *sess;

    c = pc->connection;

    if (!pc->cached) {
        return ngx_http_proxy_v2_create_session(c->pool);
    }

    /* find the session in the cached connection's pool cleanup handlers */

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_proxy_v2_cleanup_session) {
            sess = cln->data;
            sess->last_stream_id += 2;

            return sess;
        }
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "no session found for keepalive http2 connection");

    return NULL;
}


ngx_int_t
ngx_http_proxy_v2_parse_frame_header(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b, ngx_log_t *log)
{
    u_char      ch, *p;
    ngx_uint_t  state;
    enum {
        sw_start = 0,
        sw_length_2,
        sw_length_3,
        sw_type,
        sw_flags,
        sw_stream_id,
        sw_stream_id_2,
        sw_stream_id_3,
        sw_stream_id_4
    };

    state = sess->header_state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->length = ch << 16;
            state = sw_length_2;
            break;

        case sw_length_2:
            sess->length |= ch << 8;
            state = sw_length_3;
            break;

        case sw_length_3:
            sess->length |= ch;

            if (sess->length > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 frame: %uz",
                              sess->length);
                return NGX_ERROR;
            }

            state = sw_type;
            break;

        case sw_type:
            sess->type = ch;
            state = sw_flags;
            break;

        case sw_flags:
            sess->flags = ch;
            state = sw_stream_id;
            break;

        case sw_stream_id:
            sess->stream_id = (ch & 0x7f) << 24;
            state = sw_stream_id_2;
            break;

        case sw_stream_id_2:
            sess->stream_id |= ch << 16;
            state = sw_stream_id_3;
            break;

        case sw_stream_id_3:
            sess->stream_id |= ch << 8;
            state = sw_stream_id_4;
            break;

        case sw_stream_id_4:
            sess->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           sess->type, sess->length, sess->flags,
                           sess->stream_id);

            b->pos = p + 1;
            sess->header_state = sw_start;

            return NGX_OK;
        }
    }

    b->pos = p;
    sess->header_state = state;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_proxy_v2_parse_ping_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b, ngx_log_t *log)
{
    size_t  n;

    if (sess->ping_length == 0) {

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (sess->length != sizeof(sess->ping_data)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          sess->length);
            return NGX_ERROR;
        }

        if (sess->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame with ack flag");
            return NGX_ERROR;
        }
    }

    n = ngx_min((size_t) (b->last - b->pos),
                sizeof(sess->ping_data) - sess->ping_length);

    ngx_memcpy(sess->ping_data + sess->ping_length, b->pos, n);
    sess->ping_length += n;
    b->pos += n;

    if (sess->ping_length < sizeof(sess->ping_data)) {
        return NGX_AGAIN;
    }

    sess->ping_length = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http proxy ping");

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_goaway_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b, ngx_log_t *log)
{
    u_char  ch, *p, *last;
    size_t  n;

    if (sess->goaway_length == 0) {

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (sess->length < 8) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          sess->length);
            return NGX_ERROR;
        }
    }

    n = ngx_min((size_t) (b->last - b->pos),
                sess->length - sess->goaway_length);
    last = b->pos + n;

    for (p = b->pos; p < last && sess->goaway_length < 8; p++) {
        ch = *p;

        switch (sess->goaway_length) {

        case 0:
            sess->goaway_last_stream_id = (ch & 0x7f) << 24;
            break;

        case 1:
            sess->goaway_last_stream_id |= ch << 16;
            break;

        case 2:
            sess->goaway_last_stream_id |= ch << 8;
            break;

        case 3:
            sess->goaway_last_stream_id |= ch;
            break;

        case 4:
            sess->goaway_error = (ngx_uint_t) ch << 24;
            break;

        case 5:
            sess->goaway_error |= ch << 16;
            break;

        case 6:
            sess->goaway_error |= ch << 8;
            break;

        case 7:
            sess->goaway_error |= ch;
            break;
        }

        sess->goaway_length++;
    }

    /* skip debug data up to the end of this frame */

    sess->goaway_length += last - p;
    b->pos = last;

    if (sess->goaway_length < sess->length) {
        return NGX_AGAIN;
    }

    sess->goaway_length = 0;
    sess->goaway = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   sess->goaway_error, sess->goaway_last_stream_id);

    return NGX_OK;
}


static void
ngx_http_proxy_v2_cleanup_session(void *data)
{
    return;
}
