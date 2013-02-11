
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t                        *conns;
} ngx_http_upstream_least_conn_conf_t;


typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_uint_t                        *conns;

    ngx_event_get_peer_pt              get_rr_peer;
    ngx_event_free_peer_pt             free_rr_peer;
} ngx_http_upstream_lc_peer_data_t;


static ngx_int_t ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_least_conn_peer(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_free_least_conn_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void *ngx_http_upstream_least_conn_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_least_conn_commands[] = {

    { ngx_string("least_conn"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_least_conn,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_least_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_least_conn_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_least_conn_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_least_conn_module_ctx, /* module context */
    ngx_http_upstream_least_conn_commands, /* module directives */
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


static ngx_int_t
ngx_http_upstream_init_least_conn(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                            n;
    ngx_http_upstream_rr_peers_t         *peers;
    ngx_http_upstream_least_conn_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init least conn");

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    peers = us->peer.data;

    n = peers->number;

    if (peers->next) {
        n += peers->next->number;
    }

    lcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_least_conn_module);

    lcf->conns = ngx_pcalloc(cf->pool, sizeof(ngx_uint_t) * n);
    if (lcf->conns == NULL) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_least_conn_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_lc_peer_data_t     *lcp;
    ngx_http_upstream_least_conn_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init least conn peer");

    lcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_least_conn_module);

    lcp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_lc_peer_data_t));
    if (lcp == NULL) {
        return NGX_ERROR;
    }

    lcp->conns = lcf->conns;

    r->upstream->peer.data = &lcp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_least_conn_peer;
    r->upstream->peer.free = ngx_http_upstream_free_least_conn_peer;

    lcp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
    lcp->free_rr_peer = ngx_http_upstream_free_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_lc_peer_data_t  *lcp = data;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc, total;
    ngx_uint_t                     i, n, p, many;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (lcp->rrp.peers->single) {
        return lcp->get_rr_peer(pc, &lcp->rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = lcp->rrp.peers;

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (i = 0; i < peers->number; i++) {

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (lcp->rrp.tried[n] & m) {
            continue;
        }

        peer = &peers->peer[i];

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
         */

        if (best == NULL
            || lcp->conns[i] * best->weight < lcp->conns[p] * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (lcp->conns[i] * best->weight
                   == lcp->conns[p] * peer->weight)
        {
            many = 1;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, many");

        for (i = p; i < peers->number; i++) {

            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (lcp->rrp.tried[n] & m) {
                continue;
            }

            peer = &peers->peer[i];

            if (peer->down) {
                continue;
            }

            if (lcp->conns[i] * best->weight != lcp->conns[p] * peer->weight) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;
    best->checked = now;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    lcp->rrp.current = p;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    lcp->rrp.tried[n] |= m;
    lcp->conns[p]++;

    if (pc->tries == 1 && peers->next) {
        pc->tries += peers->next->number;
    }

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, backup servers");

        lcp->conns += peers->number;

        lcp->rrp.peers = peers->next;
        pc->tries = lcp->rrp.peers->number;

        n = (lcp->rrp.peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
             lcp->rrp.tried[i] = 0;
        }

        rc = ngx_http_upstream_get_least_conn_peer(pc, lcp);

        if (rc != NGX_BUSY) {
            return rc;
        }
    }

    /* all peers failed, mark them as live for quick recovery */

    for (i = 0; i < peers->number; i++) {
        peers->peer[i].fails = 0;
    }

    pc->name = peers->name;

    return NGX_BUSY;
}


static void
ngx_http_upstream_free_least_conn_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_http_upstream_lc_peer_data_t  *lcp = data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free least conn peer %ui %ui", pc->tries, state);

    if (lcp->rrp.peers->single) {
        lcp->free_rr_peer(pc, &lcp->rrp, state);
        return;
    }

    if (state == 0 && pc->tries == 0) {
        return;
    }

    lcp->conns[lcp->rrp.current]--;

    lcp->free_rr_peer(pc, &lcp->rrp, state);
}


static void *
ngx_http_upstream_least_conn_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_least_conn_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_least_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->conns = NULL;
     */

    return conf;
}


static char *
ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    uscf->peer.init_upstream = ngx_http_upstream_init_least_conn;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN
                  |NGX_HTTP_UPSTREAM_BACKUP;

    return NGX_CONF_OK;
}
