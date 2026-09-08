
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


static void
ngx_http_proxy_v2_cleanup_session(void *data)
{
    return;
}
