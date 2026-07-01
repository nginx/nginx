
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_V2)
#include <ngx_http_proxy_module.h>
#endif


typedef struct {
    ngx_uint_t                         max_cached;
    ngx_uint_t                         requests;
    ngx_msec_t                         time;
    ngx_msec_t                         timeout;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_peer_pt     original_init_peer;

    ngx_uint_t                         local; /* unsigned  local:1; */

    ngx_uint_t                         max_streams_per_connection;
    ngx_uint_t                         max_streams_total;
    ngx_uint_t                         total_active_streams;
} ngx_http_upstream_keepalive_srv_conf_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

    ngx_http_upstream_conf_t          *tag;

    ngx_uint_t                         active_streams;

    unsigned                           h2:1;
} ngx_http_upstream_keepalive_cache_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

    ngx_event_notify_peer_pt           original_notify;

    unsigned                           h2_enabled:1;

    ngx_uint_t                         max_streams_per_connection;
    ngx_uint_t                         max_streams_total;

} ngx_http_upstream_keepalive_peer_data_t;


static ngx_int_t ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void ngx_http_upstream_notify_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

static void *ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_keepalive_init_main_conf(ngx_conf_t *cf,
    void *conf);
static char *ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_http_upstream_keepalive_cache_t *
    ngx_http_upstream_keepalive_find_cached_connection(ngx_queue_t *cache,
    ngx_connection_t *c);
static void ngx_http_upstream_keepalive_adjust_total(
    ngx_http_upstream_keepalive_srv_conf_t *kcf, ngx_uint_t delta);
static void ngx_http_upstream_keepalive_prepare_connection(
    ngx_connection_t *c, ngx_peer_connection_t *pc);
static void ngx_http_upstream_keepalive_set_idle(
    ngx_http_upstream_keepalive_cache_t *item, ngx_connection_t *c,
    ngx_peer_connection_t *pc, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_get_keepalive_peer_h1(
    ngx_peer_connection_t *pc, ngx_http_upstream_keepalive_peer_data_t *kp);
static ngx_int_t ngx_http_upstream_get_keepalive_peer_h2(
    ngx_peer_connection_t *pc, ngx_http_upstream_keepalive_peer_data_t *kp);
static void ngx_http_upstream_free_keepalive_peer_h1(
    ngx_peer_connection_t *pc, ngx_http_upstream_keepalive_peer_data_t *kp,
    ngx_uint_t state);
static void ngx_http_upstream_free_keepalive_peer_h2(
    ngx_peer_connection_t *pc, ngx_http_upstream_keepalive_peer_data_t *kp,
    ngx_uint_t state);
static ngx_uint_t ngx_http_upstream_keepalive_h2_connection_bad(
    ngx_peer_connection_t *pc, ngx_uint_t state);
static void ngx_http_upstream_keepalive_drop_h2_connection(
    ngx_http_upstream_keepalive_srv_conf_t *kcf,
    ngx_http_upstream_keepalive_cache_t *item, ngx_peer_connection_t *pc);


static ngx_command_t  ngx_http_upstream_keepalive_commands[] = {

    { ngx_string("keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_keepalive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("keepalive_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, time),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { ngx_string("keepalive_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

    { ngx_string("keepalive_max_streams_per_connection"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t,
                max_streams_per_connection),
      NULL },

    { ngx_string("keepalive_max_streams_total"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, max_streams_total),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    ngx_http_upstream_keepalive_init_main_conf, /* init main configuration */

    ngx_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_keepalive_module_ctx, /* module context */
    ngx_http_upstream_keepalive_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_upstream_keepalive_cache_t *
ngx_http_upstream_keepalive_find_cached_connection(ngx_queue_t *cache,
    ngx_connection_t *c)
{
    ngx_queue_t                          *q;
    ngx_http_upstream_keepalive_cache_t  *item;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        if (item->connection == c) {
            return item;
        }
    }

    return NULL;
}


/* Acquire a cache slot for a new connection.
 * For H2: only evict connections that currently have zero active streams.
 * Returns a card removed from free or from cache (with its old conn closed).
 * Returns NULL if no safe slot (all cards busy with streams).
 */
static ngx_http_upstream_keepalive_cache_t *
ngx_http_upstream_keepalive_get_slot(ngx_http_upstream_keepalive_srv_conf_t *kcf)
{
    ngx_queue_t                          *q;
    ngx_http_upstream_keepalive_cache_t  *item;

    if (!ngx_queue_empty(&kcf->free)) {
        q = ngx_queue_head(&kcf->free);
        ngx_queue_remove(q);
        return ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
    }

    /* H2-safe eviction: only close idle (active_streams == 0) connections.
     * Walk from tail (LRU) to find the least-recent idle one.
     */
    for (q = ngx_queue_last(&kcf->cache);
         q != ngx_queue_sentinel(&kcf->cache);
         q = ngx_queue_prev(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        if (item->active_streams == 0) {
            ngx_queue_remove(q);
            ngx_http_upstream_keepalive_close(item->connection);
            return item;
        }
    }

    return NULL;
}


static void
ngx_http_upstream_keepalive_attach_new_h2(void *data, ngx_connection_t *c,
    ngx_peer_connection_t *pc)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;
    ngx_http_upstream_keepalive_cache_t      *item;
    ngx_http_upstream_t                      *u;

    if (kp == NULL) {
        return;
    }

    kcf = kp->conf;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc ? pc->log : kp->upstream ? kp->upstream->peer.log : NULL, 0,
                   "attach_new_h2: entered, h2_enabled=%d", kp->h2_enabled);

    if (!kp->h2_enabled) {
        return;
    }

    u = kp->upstream;

    item = ngx_http_upstream_keepalive_get_slot(kcf);
    if (item == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc ? pc->log : NULL, 0,
                       "attach_new_h2: get_slot returned NULL, not parking early");
        /* No safe slot (all pooled conns are busy). Do not add this
         * connection to the cache so we don't evict active work.
         * Current request can still use the new socket; it just won't
         * be offered for multiplexing to other requests.
         */
        return;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc ? pc->log : c->log, 0,
                   "attach_new_h2: slot=%p parking #%uA c=%p fd=%d "
                   "pool=%p active=1",
                   item, c->number, c, c->fd, c->pool);

    item->connection = c;
    item->active_streams = 1;
    item->h2 = 1;
    item->tag = u->conf;
    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    ngx_queue_insert_head(&kcf->cache, &item->queue);

    /*
     * We do not call prepare_connection() here.  For a freshly created
     * connection the core upstream code (after this hook returns) will
     * initialize the pool, logs, c->data = r, handlers etc.  We only need
     * the item in the cache with active_streams=1 so that concurrent
     * get_keepalive_peer_h2 calls can find and share this connection.
     * Do not call set_idle() — this conn is still in use by the current
     * request.
     */
}


static void
ngx_http_upstream_keepalive_adjust_total(
    ngx_http_upstream_keepalive_srv_conf_t *kcf, ngx_uint_t delta)
{
    if (delta == 0) {
        return;
    }

    if (delta > kcf->total_active_streams) {
        kcf->total_active_streams = 0;
        return;
    }

    kcf->total_active_streams -= delta;
}


static void
ngx_http_upstream_keepalive_prepare_connection(ngx_connection_t *c,
    ngx_peer_connection_t *pc)
{
    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
}


static void
ngx_http_upstream_keepalive_set_idle(
    ngx_http_upstream_keepalive_cache_t *item, ngx_connection_t *c,
    ngx_peer_connection_t *pc, ngx_http_upstream_t *u)
{
    c->read->delayed = 0;
    ngx_add_timer(c->read, item->conf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
    c->read->handler = ngx_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->tag = u->conf;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        ngx_http_upstream_keepalive_close_handler(c->read);
    }
}


static ngx_int_t
ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
#endif

    /* Always install notify wrapper (after the L1 original_init_peer has run).
     * This ensures NGX_HTTP_UPSTREAM_NOTIFY_CONNECT is delivered for early
     * H2 parking even when no other module (sticky/least_time) provided a
     * base notify. We save whatever was there (possibly NULL) and chain.
     */
    kp->original_notify = r->upstream->peer.notify;
    r->upstream->peer.notify = ngx_http_upstream_notify_keepalive_peer;

#if (NGX_HTTP_V2)
    {
        ngx_http_proxy_loc_conf_t  *plcf;

        plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
        if (plcf && plcf->http_version == NGX_HTTP_VERSION_20) {
            kp->h2_enabled = 1;
            if (kp->upstream) {
                kp->upstream->http2 = 1;
            }

            /* if user did not set the H2 keepalive knobs, apply defaults for this request */
            if (kcf->max_streams_per_connection == NGX_CONF_UNSET_UINT) {
                kp->max_streams_per_connection = 100;  /* sensible default */
            } else {
                kp->max_streams_per_connection = kcf->max_streams_per_connection;
            }

            if (kcf->max_streams_total == NGX_CONF_UNSET_UINT) {
                kp->max_streams_total = kp->max_streams_per_connection * kcf->max_cached;
            } else {
                kp->max_streams_total = kcf->max_streams_total;
            }
        }
    }
#endif

    if (!kp->h2_enabled) {
        kp->max_streams_per_connection = kcf->max_streams_per_connection;
        kp->max_streams_total = kcf->max_streams_total;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_peer_h1(ngx_peer_connection_t *pc,
    ngx_http_upstream_keepalive_peer_data_t *kp)
{
    ngx_http_upstream_keepalive_cache_t  *item;

    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (kp->conf->local && item->tag != kp->upstream->conf) {
            continue;
        }

        if (item->h2) {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);

            ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "get keepalive peer: using #%uA c=%p fd=%d pool=%p",
                           c->number, c, c->fd, c->pool);

            ngx_http_upstream_keepalive_prepare_connection(c, pc);

            pc->connection = c;
            pc->cached = 1;

            return NGX_DONE;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_peer_h2(ngx_peer_connection_t *pc,
    ngx_http_upstream_keepalive_peer_data_t *kp)
{
    ngx_http_upstream_keepalive_srv_conf_t  *kcf;
    ngx_http_upstream_keepalive_cache_t     *item, *best;

    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;
    ngx_uint_t         best_active;

    kcf = kp->conf;

    if (kcf->total_active_streams >= kp->max_streams_total) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get keepalive peer: total stream limit reached");

        return NGX_BUSY;
    }

    cache = &kcf->cache;
    best = NULL;
    best_active = NGX_MAX_UINT32_VALUE;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (kp->conf->local && item->tag != kp->upstream->conf) {
            continue;
        }

        if (!item->h2) {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            != 0)
        {
            continue;
        }

        if (item->active_streams >= kp->max_streams_per_connection) {
            continue;
        }

        if (item->active_streams < best_active) {
            best = item;
            best_active = item->active_streams;
        }
    }

    if (best == NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                        "get_h2: no suitable cached conn found (best==NULL), will create new. "
                        "total_active=%ui max_total=%ui",
                        kcf->total_active_streams, kp->max_streams_total);
        kcf->total_active_streams++;

        return NGX_OK;
    }

    c = best->connection;

    best->active_streams++;
    kcf->total_active_streams++;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using #%uA c=%p fd=%d pool=%p "
                   "slot=%p active_streams=%ui total=%ui",
                   c->number, c, c->fd, c->pool, best,
                   best->active_streams, kcf->total_active_streams);

    ngx_http_upstream_keepalive_prepare_connection(c, pc);

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    ngx_int_t  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    if (kp->h2_enabled) {
        return ngx_http_upstream_get_keepalive_peer_h2(pc, kp);
    }

    return ngx_http_upstream_get_keepalive_peer_h1(pc, kp);
}


static ngx_uint_t
ngx_http_upstream_keepalive_h2_connection_bad(ngx_peer_connection_t *pc,
    ngx_uint_t state)
{
    ngx_connection_t  *c;

    if (state & NGX_PEER_FAILED) {
        return 1;
    }

    c = pc->connection;

    if (c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        return 1;
    }

    return 0;
}


static void
ngx_http_upstream_keepalive_drop_h2_connection(
    ngx_http_upstream_keepalive_srv_conf_t *kcf,
    ngx_http_upstream_keepalive_cache_t *item, ngx_peer_connection_t *pc)
{
    ngx_connection_t  *c;

    if (item->active_streams > 0) {
        ngx_http_upstream_keepalive_adjust_total(kcf, item->active_streams);
        item->active_streams = 0;
    }

    c = item->connection;

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&kcf->free, &item->queue);
    item->connection = NULL;

    if (c) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "keepalive h2 drop: #%uA c=%p fd=%d pool=%p slot=%p",
                       c->number, c, c->fd, c->pool, item);

        ngx_http_upstream_keepalive_close(c);
    }

    pc->connection = NULL;
}


static void
ngx_http_upstream_free_keepalive_peer_h1(ngx_peer_connection_t *pc,
    ngx_http_upstream_keepalive_peer_data_t *kp, ngx_uint_t state)
{
    ngx_http_upstream_keepalive_cache_t  *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    u = kp->upstream;
    c = pc->connection;

    if (ngx_queue_empty(&kp->conf->free)) {

        q = ngx_queue_last(&kp->conf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        ngx_http_upstream_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
    }

    ngx_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;
    item->tag = u->conf;
    item->h2 = 0;

    pc->connection = NULL;

    ngx_http_upstream_keepalive_set_idle(item, c, pc, u);
}


static void
ngx_http_upstream_free_keepalive_peer_h2(ngx_peer_connection_t *pc,
    ngx_http_upstream_keepalive_peer_data_t *kp, ngx_uint_t state)
{
    ngx_http_upstream_keepalive_srv_conf_t  *kcf;
    ngx_http_upstream_keepalive_cache_t     *item;

    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    kcf = kp->conf;
    u = kp->upstream;
    c = pc->connection;

    item = ngx_http_upstream_keepalive_find_cached_connection(&kcf->cache, c);

    if (item) {

        if (item->active_streams > 0) {
            item->active_streams--;
            ngx_http_upstream_keepalive_adjust_total(kcf, 1);
        }

        pc->connection = NULL;

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "keepalive h2 free: #%uA c=%p fd=%d pool=%p slot=%p "
                       "active_streams=%ui total=%ui",
                       c->number, c, c->fd, c->pool, item,
                       item->active_streams, kcf->total_active_streams);

        if (item->active_streams > 0) {
            return;
        }

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "keepalive h2 idle: #%uA c=%p fd=%d last stream done",
                       c->number, c, c->fd);

        ngx_http_upstream_keepalive_set_idle(item, c, pc, u);

        return;
    }

    if (kcf->total_active_streams > 0) {
        kcf->total_active_streams--;
    }

    item = ngx_http_upstream_keepalive_get_slot(kcf);
    if (item == NULL) {
        /* No safe slot available (all pooled connections are busy).
         * Do not park this connection. The socket will be closed by
         * the normal upstream path after this request/stream ends.
         */
        return;
    }

    ngx_queue_insert_head(&kcf->cache, &item->queue);

    item->connection = c;
    item->active_streams = 0;
    item->h2 = 1;
    item->tag = u->conf;

    pc->connection = NULL;

    ngx_http_upstream_keepalive_set_idle(item, c, pc, u);
}


static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;
    ngx_http_upstream_keepalive_cache_t     *item;

    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    u = kp->upstream;
    c = pc->connection;
    kcf = kp->conf;

    /*
     * H2 multiplex: cached connections use per-stream teardown.
     * Do not apply the H1 !u->keepalive gate to shared sockets.
     */
    if (kp->h2_enabled && c != NULL) {
        item = ngx_http_upstream_keepalive_find_cached_connection(&kcf->cache,
                                                                    c);
        if (item != NULL) {
            if (ngx_http_upstream_keepalive_h2_connection_bad(pc, state)) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "keepalive h2 free cached bad: #%uA c=%p fd=%d",
                               c->number, c, c->fd);

                ngx_http_upstream_keepalive_drop_h2_connection(kcf, item, pc);

            } else {
                ngx_http_upstream_free_keepalive_peer_h2(pc, kp, state);
            }

            goto done;
        }
    }

    if (ngx_http_upstream_keepalive_h2_connection_bad(pc, state)) {
        goto invalid;
    }

    if (c->requests >= kcf->requests) {
        goto invalid;
    }

    if (ngx_current_msec - c->start_time > kcf->time) {
        goto invalid;
    }

    if (!u->keepalive) {
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

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving #%uA c=%p fd=%d pool=%p",
                   c->number, c, c->fd, c->pool);

    if (kp->h2_enabled) {
        ngx_http_upstream_free_keepalive_peer_h2(pc, kp, state);
        goto done;
    }

    ngx_http_upstream_free_keepalive_peer_h1(pc, kp, state);

    goto done;

invalid:

    if (kp->h2_enabled) {
        item = c ? ngx_http_upstream_keepalive_find_cached_connection(
                                                        &kcf->cache, c) : NULL;

        if (item) {
            ngx_http_upstream_keepalive_drop_h2_connection(kcf, item, pc);

        } else if (kcf->total_active_streams > 0) {
            kcf->total_active_streams--;
        }
    }

done:

    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;
    ngx_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    if (item->h2) {
        if (item->active_streams > 0) {
            ngx_http_upstream_keepalive_adjust_total(conf,
                                                    item->active_streams);
            item->active_streams = 0;
            item->h2 = 0;
        }
    }

    ngx_http_upstream_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
    item->connection = NULL;
}


static void
ngx_http_upstream_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void
ngx_http_upstream_notify_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "notify keepalive peer: type=%ui pc=%p",
                   type, pc);

    if (type == NGX_HTTP_UPSTREAM_NOTIFY_CONNECT) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "notify keepalive: CONNECT received, kp=%p", kp);
        if (kp && kp->h2_enabled) {
            ngx_connection_t *c = pc->connection;
            if (c != NULL) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                               "notify keepalive: calling attach for "
                               "#%uA c=%p fd=%d pool=%p",
                               c->number, c, c->fd, c->pool);
                ngx_http_upstream_keepalive_attach_new_h2(kp, c, pc);
            }
        }
    }

    if (kp && kp->original_notify) {
        kp->original_notify(pc, kp->data, type);
    }
}


static void *
ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_peer = NULL;
     *     conf->local = 0;
     *     conf->total_active_streams = 0;
     */

    conf->time = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->requests = NGX_CONF_UNSET_UINT;
    conf->max_cached = NGX_CONF_UNSET_UINT;
    conf->max_streams_per_connection = NGX_CONF_UNSET_UINT;
    conf->max_streams_total = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_upstream_keepalive_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                                i, j;
    ngx_http_upstream_srv_conf_t            **uscfp;
    ngx_http_upstream_main_conf_t            *umcf;
    ngx_http_upstream_keepalive_cache_t      *cached;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        /* skip implicit upstreams */
        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        kcf = ngx_http_conf_upstream_srv_conf(uscfp[i],
                                            ngx_http_upstream_keepalive_module);

        if (kcf->max_cached == 0) {
            continue;
        }

        ngx_conf_init_msec_value(kcf->time, 3600000);
        ngx_conf_init_msec_value(kcf->timeout, 60000);
        ngx_conf_init_uint_value(kcf->requests, 1000);

        if (kcf->max_cached == NGX_CONF_UNSET_UINT) {
            kcf->local = 1;
            kcf->max_cached = 32;
        }

        if (kcf->max_streams_per_connection != NGX_CONF_UNSET_UINT) {

            if (kcf->max_streams_total == NGX_CONF_UNSET_UINT) {
                kcf->max_streams_total =
                    kcf->max_streams_per_connection * kcf->max_cached;
            }

            if (kcf->max_streams_total < kcf->max_streams_per_connection) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "keepalive_max_streams_total must be "
                                   "greater than or equal to "
                                   "keepalive_max_streams_per_connection");
                return NGX_CONF_ERROR;
            }
        }

        kcf->original_init_peer = uscfp[i]->peer.init;

        uscfp[i]->peer.init = ngx_http_upstream_init_keepalive_peer;

        /* allocate cache items and add to free queue */

        cached = ngx_pcalloc(cf->pool,
                 sizeof(ngx_http_upstream_keepalive_cache_t) * kcf->max_cached);
        if (cached == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_queue_init(&kcf->cache);
        ngx_queue_init(&kcf->free);

        for (j = 0; j < kcf->max_cached; j++) {
            ngx_queue_insert_head(&kcf->free, &cached[j].queue);
            cached[j].conf = kcf;
            cached[j].active_streams = 0;
            cached[j].h2 = 0;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;

    if (kcf->max_cached != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    kcf->max_cached = n;

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "local") == 0) {
            kcf->local = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
