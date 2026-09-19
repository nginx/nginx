
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


static void ngx_http_proxy_v2_session_cleanup(void *data);


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

    (*session)->connection = c;
    (*session)->stream = NULL;
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
