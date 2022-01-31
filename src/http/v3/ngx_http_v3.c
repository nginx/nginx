
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_v3_keepalive_handler(ngx_event_t *ev);
static void ngx_http_v3_cleanup_session(void *data);


ngx_int_t
ngx_http_v3_init_session(ngx_connection_t *c)
{
    ngx_connection_t       *pc;
    ngx_pool_cleanup_t     *cln;
    ngx_http_connection_t  *hc;
    ngx_http_v3_session_t  *h3c;

    pc = c->quic->parent;
    hc = pc->data;

    if (hc->v3_session) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 init session");

    h3c = ngx_pcalloc(pc->pool, sizeof(ngx_http_v3_session_t));
    if (h3c == NULL) {
        goto failed;
    }

    h3c->max_push_id = (uint64_t) -1;
    h3c->goaway_push_id = (uint64_t) -1;

    ngx_queue_init(&h3c->blocked);
    ngx_queue_init(&h3c->pushing);

    h3c->keepalive.log = pc->log;
    h3c->keepalive.data = pc;
    h3c->keepalive.handler = ngx_http_v3_keepalive_handler;
    h3c->keepalive.cancelable = 1;

    cln = ngx_pool_cleanup_add(pc->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_v3_cleanup_session;
    cln->data = h3c;

    hc->v3_session = h3c;

    return ngx_http_v3_send_settings(c);

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to create http3 session");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR,
                                    "failed to create http3 session");
    return NGX_ERROR;
}


static void
ngx_http_v3_keepalive_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 keepalive handler");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR,
                                    "keepalive timeout");
}


static void
ngx_http_v3_cleanup_session(void *data)
{
    ngx_http_v3_session_t  *h3c = data;

    ngx_http_v3_cleanup_table(h3c);

    if (h3c->keepalive.timer_set) {
        ngx_del_timer(&h3c->keepalive);
    }
}


ngx_int_t
ngx_http_v3_check_flood(ngx_connection_t *c)
{
    ngx_http_v3_session_t  *h3c;

    h3c = ngx_http_v3_get_session(c);

    if (h3c->total_bytes / 8 > h3c->payload_bytes + 1048576) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "http3 flood detected");

        ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR,
                                        "HTTP/3 flood detected");
        return NGX_ERROR;
    }

    return NGX_OK;
}
