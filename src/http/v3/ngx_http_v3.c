
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_v3_cleanup_session(void *data);


ngx_int_t
ngx_http_v3_init_session(ngx_connection_t *c)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_v3_session_t  *h3c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 init session");

    h3c = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_session_t));
    if (h3c == NULL) {
        goto failed;
    }

    h3c->connection = c;

    ngx_queue_init(&h3c->queue);

    h3c->table.send_insert_count.log = c->log;
    h3c->table.send_insert_count.data = c;
    h3c->table.send_insert_count.handler = ngx_http_v3_inc_insert_count_handler;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_v3_cleanup_session;
    cln->data = h3c;

    c->data = h3c;

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to create http3 session");
    return NGX_ERROR;
}


static void
ngx_http_v3_cleanup_session(void *data)
{
    ngx_http_v3_session_t  *h3c = data;

    ngx_http_v3_cleanup_table(h3c);

    if (h3c->table.send_insert_count.posted) {
        ngx_delete_posted_event(&h3c->table.send_insert_count);
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


void
ngx_http_v3_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    if (ngx_quic_shutdown(c) == NGX_AGAIN) {
        c->ssl->handler = ngx_http_v3_close_connection;
        return;
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}
