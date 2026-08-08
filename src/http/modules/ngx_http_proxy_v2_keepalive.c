
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_module.h>
#include <ngx_http_proxy_v2_keepalive.h>


typedef struct {
    ngx_http_upstream_srv_conf_t        *upstream;

    ngx_uint_t                         max_cached;
    ngx_uint_t                         requests;
    ngx_msec_t                         time;
    ngx_msec_t                         timeout;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_proxy_v2_keepalive_pool_t;


typedef struct {
    ngx_array_t                         pools;
} ngx_http_proxy_v2_keepalive_main_conf_t;


typedef struct {
    ngx_http_proxy_v2_keepalive_pool_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

} ngx_http_proxy_v2_keepalive_cache_t;


typedef struct {
    ngx_http_proxy_v2_keepalive_pool_t  *conf;

    ngx_http_request_t                *request;
    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

    ngx_event_notify_peer_pt           original_notify;

} ngx_http_proxy_v2_keepalive_peer_data_t;


static ngx_int_t ngx_http_proxy_v2_keepalive_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_keepalive_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_proxy_v2_keepalive_close_connection(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_v2_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_proxy_v2_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void ngx_http_proxy_v2_keepalive_notify_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

static ngx_http_proxy_v2_keepalive_pool_t *
    ngx_http_proxy_v2_keepalive_find_pool(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_proxy_v2_keepalive_init_pool(ngx_conf_t *cf,
    ngx_http_proxy_v2_keepalive_pool_t *kcf);


ngx_int_t
ngx_http_proxy_v2_keepalive_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_proxy_v2_keepalive_peer_data_t  *kp;
    ngx_http_proxy_v2_keepalive_pool_t       *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init proxy v2 keepalive peer");

    kcf = ngx_http_proxy_v2_keepalive_find_pool(r, us);
    if (kcf == NULL) {
        return us->peer.init(r, us);
    }

    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp = ngx_palloc(r->pool, sizeof(ngx_http_proxy_v2_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->request = r;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_proxy_v2_keepalive_get_peer;
    r->upstream->peer.free = ngx_http_proxy_v2_keepalive_free_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_proxy_v2_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_proxy_v2_keepalive_save_session;
#endif

    if (r->upstream->peer.notify) {
        kp->original_notify = r->upstream->peer.notify;
        r->upstream->peer.notify = ngx_http_proxy_v2_keepalive_notify_peer;
    }

    return NGX_OK;
}


static ngx_http_proxy_v2_keepalive_pool_t *
ngx_http_proxy_v2_keepalive_find_pool(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                                i;
    ngx_http_proxy_v2_keepalive_pool_t       *kcf;
    ngx_http_proxy_v2_keepalive_main_conf_t  *kmcf;

    kmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_v2_module);

    kcf = kmcf->pools.elts;

    for (i = 0; i < kmcf->pools.nelts; i++) {
        if (kcf[i].upstream == us) {
            return &kcf[i];
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_proxy_v2_keepalive_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_keepalive_peer_data_t  *kp = data;
    ngx_http_proxy_v2_keepalive_cache_t      *item;

    ngx_int_t                   rc;
    ngx_queue_t                *q, *cache;
    ngx_connection_t           *c;
    ngx_http_proxy_v2_conn_t   *h2c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_proxy_v2_keepalive_cache_t, queue);
        c = item->connection;
        h2c = c->data;

        if (!c->idle || c->close || c->error
            || c->read->ready || c->read->eof || c->read->error
            || c->read->timedout || c->write->error || c->write->timedout
            || h2c == NULL || h2c->request != NULL || h2c->data != item
            || h2c->connection != c
            || h2c->goaway
            || h2c->parse.state != ngx_http_proxy_v2_st_start
            || h2c->buffer.pos != h2c->buffer.last
            || ngx_http_proxy_v2_connection_output_pending(c, h2c))
        {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;

    h2c->data = NULL;

    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


static void
ngx_http_proxy_v2_keepalive_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_proxy_v2_keepalive_peer_data_t  *kp = data;
    ngx_http_proxy_v2_keepalive_cache_t      *item;

    ngx_queue_t               *q;
    ngx_connection_t          *c;
    ngx_http_upstream_t       *u;
    ngx_http_proxy_v2_ctx_t   *ctx;
    ngx_http_proxy_v2_conn_t  *h2c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;
    ctx = ngx_http_get_module_ctx(kp->request, ngx_http_proxy_v2_module);

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->close
        || c->error
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (c->requests >= kp->conf->requests) {
        goto invalid;
    }

    if (ngx_current_msec - c->start_time > kp->conf->time) {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (ctx == NULL || ctx->connection == NULL
        || c->data != ctx->connection)
    {
        goto invalid;
    }

    h2c = c->data;

    if (h2c->connection != c || h2c->request != kp->request
        || h2c->goaway || ngx_http_proxy_v2_output_pending(c, ctx))
    {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (ngx_terminate || ngx_exiting) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&kp->conf->free)) {

        q = ngx_queue_last(&kp->conf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_proxy_v2_keepalive_cache_t, queue);

        ngx_http_proxy_v2_keepalive_close_connection(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_proxy_v2_keepalive_cache_t, queue);
    }

    ngx_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;
    pc->connection = NULL;

    h2c->request = NULL;
    h2c->data = item;

    c->read->delayed = 0;
    ngx_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* keep the connection handlers for idle control frames */

    c->data = h2c;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        c->read->handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


void
ngx_http_proxy_v2_keepalive_close_idle(ngx_connection_t *c)
{
    ngx_http_proxy_v2_keepalive_pool_t  *conf;
    ngx_http_proxy_v2_keepalive_cache_t *item;
    ngx_http_proxy_v2_conn_t            *h2c;

    h2c = c->data;

    if (!c->idle || h2c == NULL || h2c->connection != c
        || h2c->data == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "cannot remove proxy http2 connection from "
                      "keepalive cache");
        ngx_http_proxy_v2_keepalive_close_connection(c);
        return;
    }

    item = h2c->data;

    if (item->connection != c) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "proxy http2 keepalive item changed ownership");
        ngx_http_proxy_v2_keepalive_close_connection(c);
        return;
    }

    conf = item->conf;

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);

    h2c->data = NULL;
    item->connection = NULL;

    ngx_http_proxy_v2_keepalive_close_connection(c);
}


static void
ngx_http_proxy_v2_keepalive_close_connection(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_proxy_v2_keepalive_close_connection;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_proxy_v2_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_proxy_v2_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void
ngx_http_proxy_v2_keepalive_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_proxy_v2_keepalive_peer_data_t  *kp = data;

    kp->original_notify(pc, kp->data, type);
}


void *
ngx_http_proxy_v2_keepalive_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_v2_keepalive_main_conf_t  *kmcf;

    kmcf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_proxy_v2_keepalive_main_conf_t));
    if (kmcf == NULL) {
        return NULL;
    }

    return kmcf;
}


char *
ngx_http_proxy_v2_keepalive_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_proxy_v2_keepalive_main_conf_t *kmcf = conf;

    ngx_uint_t                                i, n;
    ngx_http_upstream_srv_conf_t            **uscfp;
    ngx_http_upstream_main_conf_t            *umcf;
    ngx_http_proxy_v2_keepalive_pool_t       *kcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    n = ngx_max(umcf->upstreams.nelts, 1);

    if (ngx_array_init(&kmcf->pools, cf->pool, n,
                       sizeof(ngx_http_proxy_v2_keepalive_pool_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        kcf = ngx_array_push(&kmcf->pools);
        if (kcf == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(kcf, sizeof(ngx_http_proxy_v2_keepalive_pool_t));

        kcf->upstream = uscfp[i];
        kcf->original_init_peer = uscfp[i]->peer.init;

        if (kcf->original_init_peer == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "proxy v2 upstream peer is not initialized");
            return NGX_CONF_ERROR;
        }

        if (ngx_http_proxy_v2_keepalive_init_pool(cf, kcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_v2_keepalive_init_pool(ngx_conf_t *cf,
    ngx_http_proxy_v2_keepalive_pool_t *kcf)
{
    ngx_uint_t                            i;
    ngx_http_proxy_v2_keepalive_cache_t  *cached;

    kcf->max_cached = 32;
    kcf->requests = 1000;
    kcf->time = 3600000;
    kcf->timeout = 60000;
    cached = ngx_pcalloc(cf->pool,
                 sizeof(ngx_http_proxy_v2_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&kcf->cache);
    ngx_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        ngx_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return NGX_OK;
}
