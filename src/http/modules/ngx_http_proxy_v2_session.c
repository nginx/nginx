
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
