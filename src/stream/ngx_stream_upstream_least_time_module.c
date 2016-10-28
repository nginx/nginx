
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define NGX_STREAM_UPSTREAM_LT_CONNECT     0
#define NGX_STREAM_UPSTREAM_LT_FIRST_BYTE  1
#define NGX_STREAM_UPSTREAM_LT_LAST_BYTE   2


typedef struct {
    ngx_uint_t                           mode;
    ngx_uint_t                           use_inflight;
                                                /* unsigned  use_inflight:1; */
} ngx_stream_upstream_lt_conf_t;


typedef struct {
    /* the round robin data must be first */
    ngx_stream_upstream_rr_peer_data_t   rrp;

    ngx_stream_upstream_lt_conf_t       *conf;
    ngx_uint_t                           inflight;  /* unsigned  inflight:1; */
    ngx_stream_upstream_t               *upstream;
} ngx_stream_upstream_lt_peer_data_t;


static ngx_int_t ngx_stream_upstream_init_least_time_peer(
    ngx_stream_session_t *s, ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_least_time_peer(
    ngx_peer_connection_t *pc, void *data);
static ngx_uint_t ngx_stream_upstream_least_time_eta(
    ngx_stream_upstream_lt_peer_data_t *ltp,
    ngx_stream_upstream_rr_peer_t *peer);
static void ngx_stream_upstream_least_time_notify(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
static void ngx_stream_upstream_least_time_inflight_done(
    ngx_stream_upstream_lt_peer_data_t *ltp,
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *peer,
    ngx_msec_t last);
static void ngx_stream_upstream_free_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void *ngx_stream_upstream_least_time_create_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_stream_upstream_least_time_mode[] = {
    { ngx_string("connect"), NGX_STREAM_UPSTREAM_LT_CONNECT },
    { ngx_string("first_byte"), NGX_STREAM_UPSTREAM_LT_FIRST_BYTE },
    { ngx_string("last_byte"), NGX_STREAM_UPSTREAM_LT_LAST_BYTE },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_stream_upstream_least_time_commands[] = {

    { ngx_string("least_time"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE12,
      ngx_stream_upstream_least_time,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_upstream_lt_conf_t, mode),
      &ngx_stream_upstream_least_time_mode },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_least_time_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_upstream_least_time_create_conf,
                                           /* create server configuration */
    NULL,                                  /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_least_time_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_least_time_module_ctx, /* module context */
    ngx_stream_upstream_least_time_commands,    /* module directives */
    NGX_STREAM_MODULE,                          /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_upstream_init_least_time(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0,
                   "init least time");

    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_least_time_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_least_time_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_lt_conf_t       *ltcf;
    ngx_stream_upstream_lt_peer_data_t  *ltp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init least time peer");

    ltp = ngx_pcalloc(s->connection->pool,
                      sizeof(ngx_stream_upstream_lt_peer_data_t));
    if (ltp == NULL) {
        return NGX_ERROR;
    }

    s->upstream->peer.data = &ltp->rrp;

    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_stream_upstream_get_least_time_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_least_time_peer;

    ltp->upstream = s->upstream;

    ltcf = ngx_stream_conf_upstream_srv_conf(us,
                                        ngx_stream_upstream_least_time_module);

    if (ltcf->use_inflight) {
        s->upstream->peer.notify = ngx_stream_upstream_least_time_notify;
    }

    ltp->conf = ltcf;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_least_time_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_lt_peer_data_t *ltp = data;

    time_t                               now;
    uintptr_t                            m;
    ngx_int_t                            rc, total;
    ngx_uint_t                           i, n, p, many, eta, best_eta;
    ngx_msec_t                           ift;
    ngx_stream_upstream_rr_peer_t       *peer, *best;
    ngx_stream_upstream_rr_peers_t      *peers;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get least time peer, try: %ui", pc->tries);

    rrp = &ltp->rrp;

    if (rrp->peers->single) {
        return ngx_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = rrp->peers;

    ngx_stream_upstream_rr_peers_wlock(peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (peers->config && rrp->config != *peers->config) {
        goto busy;
    }
#endif

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
    best_eta = 0;
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        if (peer->inflight_reqs > 0) {

            ift = peer->inflight_last / peer->inflight_reqs
                  + (ngx_current_msec - peer->inflight_reqs_changed);

            ngx_stream_upstream_response_time_avg(&peer->inflight_time, ift);
        }

        /*
         * select peer with least estimated time of processing; if there are
         * multiple peers with the same time, select based on round-robin
         */

        eta = ngx_stream_upstream_least_time_eta(ltp, peer);

        if (best == NULL
            || eta * best->weight < best_eta * peer->weight)
        {
            best = peer;
            best_eta = eta;
            many = 0;
            p = i;

        } else if (eta * best->weight == best_eta * peer->weight) {
            many = 1;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least time peer, no peer found");

        goto failed;
    }

    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least time peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            if (peer->down) {
                continue;
            }

            eta = ngx_stream_upstream_least_time_eta(ltp, peer);

            if (eta * best->weight != best_eta * peer->weight) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
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

    if (ltp->conf->use_inflight) {
        if (best->inflight_reqs > 0) {
            /* account time spent by inflight requests */
            best->inflight_last +=
                               (ngx_current_msec - best->inflight_reqs_changed)
                               * best->inflight_reqs;
        }

        best->inflight_reqs_changed = ngx_current_msec;
        best->inflight_reqs++;

        ltp->inflight = 1;
    }

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    rrp->current = best;
    ngx_stream_upstream_rr_peer_ref(peers, best);

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least time peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
             rrp->tried[i] = 0;
        }

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_least_time_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_stream_upstream_rr_peers_wlock(peers);
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
busy:
#endif

    ngx_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}


static ngx_uint_t
ngx_stream_upstream_least_time_eta(ngx_stream_upstream_lt_peer_data_t *ltp,
    ngx_stream_upstream_rr_peer_t *peer)
{
    time_t      now;
    ngx_msec_t  rt;

    switch (ltp->conf->mode) {

    case NGX_STREAM_UPSTREAM_LT_FIRST_BYTE:
        rt = peer->first_byte_time;
        break;

    case NGX_STREAM_UPSTREAM_LT_CONNECT:
        rt = peer->connect_time;
        break;

    default: /* NGX_STREAM_UPSTREAM_LT_LAST_BYTE */
        rt = peer->response_time;
    }

    now = ngx_time();

    if (now - peer->checked > peer->fail_timeout) {
        /*
         * once in fail_timeout make response time of a peer 2 times
         * lower to give chances to slow peers
         */
        rt >>= (now - peer->checked) / (peer->fail_timeout + 1);
    }

    if (peer->inflight_reqs > 0) {
        /*
         * average inflight time exceeding average response time indicates
         * bad (low priority) peer
         */
        rt = ngx_max(rt, peer->inflight_time);
    }

    if (rt > 5000) {
        /*
         * consider peers with response time greater than max equally bad
         * and thus fallback to least_conns
         */
        rt = 5000;

    } else {
        /*
         * divide response times into clusters to allow round-robin for peers
         * with close response times
         */
        rt += 20 - rt % 20;
    }

    /*
     * estimated time peer has to spend to finish processing current requests
     */
    return rt * (1 + peer->conns);
}


static void
ngx_stream_upstream_least_time_notify(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_stream_upstream_lt_peer_data_t *ltp = data;

    ngx_msec_t                           last, *metric;
    ngx_stream_upstream_t               *u;
    ngx_stream_upstream_rr_peer_t       *peer;
    ngx_stream_upstream_rr_peers_t      *peers;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    rrp = &ltp->rrp;

    peers = rrp->peers;
    peer = rrp->current;

    u = ltp->upstream;

    /*
     * Only update average time here if needed for balancing.
     * Otherwise, it will be updated in peer.free().
     */

#if (NGX_SUPPRESS_WARN)
    last = 0;
#endif
    metric = NULL;

    switch (type) {

    case NGX_STREAM_UPSTREAM_NOTIFY_CONNECT:

        if (ltp->conf->mode == NGX_STREAM_UPSTREAM_LT_CONNECT) {
            last = u->state->connect_time;
            metric = &peer->connect_time;
        }

        break;

    case NGX_STREAM_UPSTREAM_NOTIFY_FIRST_BYTE:

        if (ltp->conf->mode == NGX_STREAM_UPSTREAM_LT_FIRST_BYTE) {
            last = u->state->first_byte_time;
            metric = &peer->first_byte_time;
        }

        break;
    }

    ngx_stream_upstream_rr_peers_rlock(peers);
    ngx_stream_upstream_rr_peer_lock(peers, peer);

    if (metric) {
        ngx_stream_upstream_response_time_avg(metric, last);

        if (ltp->inflight) {
            ngx_stream_upstream_least_time_inflight_done(ltp, peers, peer,
                                                         last);
        }
    }

    ngx_stream_upstream_notify_round_robin_peer_locked(pc, data, type);
}


static void
ngx_stream_upstream_least_time_inflight_done(
    ngx_stream_upstream_lt_peer_data_t *ltp,
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *peer,
    ngx_msec_t last)
{
    if (peer->inflight_reqs == 1) {
        /* no more inflight requests */
        peer->inflight_last = 0;

    } else {

        /*
         * account time spent by inflight requests and forget about
         * request "completed" right now
         */
        peer->inflight_last += (ngx_current_msec - peer->inflight_reqs_changed)
                               * peer->inflight_reqs - last;
        peer->inflight_reqs_changed = ngx_current_msec;
    }

    peer->inflight_reqs--;
    ltp->inflight = 0;
}


static void
ngx_stream_upstream_free_least_time_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_stream_upstream_lt_peer_data_t *ltp = data;

    ngx_stream_upstream_t               *u;
    ngx_stream_upstream_rr_peer_t       *peer;
    ngx_stream_upstream_rr_peers_t      *peers;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "free least time peer");

    rrp = &ltp->rrp;
    peers = rrp->peers;
    peer = rrp->current;

    u = ltp->upstream;

    ngx_stream_upstream_rr_peers_rlock(peers);
    ngx_stream_upstream_rr_peer_lock(peers, peer);

    if (ltp->inflight) {
        ngx_stream_upstream_least_time_inflight_done(ltp, peers, peer,
                                                     u->state->response_time);
    }

    /*
     * only successful attempts are accounted to mitigate preferring
     * of failing peers
     */
    if (!(state & (NGX_PEER_FAILED|NGX_PEER_NEXT))) {
        ngx_stream_upstream_response_time_avg(&peer->response_time,
                                              u->state->response_time);

        if (!ltp->conf->use_inflight
            || ltp->conf->mode != NGX_STREAM_UPSTREAM_LT_CONNECT)
        {
            ngx_stream_upstream_response_time_avg(&peer->connect_time,
                                                  u->state->connect_time);
        }

        if (u->state->first_byte_time != (ngx_msec_t) -1
            && (!ltp->conf->use_inflight
                || ltp->conf->mode != NGX_STREAM_UPSTREAM_LT_FIRST_BYTE))
        {
            ngx_stream_upstream_response_time_avg(&peer->first_byte_time,
                                                  u->state->first_byte_time);
        }
    }

    ngx_stream_upstream_free_round_robin_peer_locked(pc, rrp, state);
}


static void *
ngx_stream_upstream_least_time_create_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_lt_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_lt_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->use_inflight = 0;
     */

    conf->mode = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_upstream_least_time(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_stream_upstream_lt_conf_t   *ltcf;
    ngx_stream_upstream_srv_conf_t  *uscf;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_stream_upstream_init_least_time;

    uscf->flags = NGX_STREAM_UPSTREAM_CREATE
                  |NGX_STREAM_UPSTREAM_MODIFY
                  |NGX_STREAM_UPSTREAM_WEIGHT
                  |NGX_STREAM_UPSTREAM_MAX_CONNS
                  |NGX_STREAM_UPSTREAM_MAX_FAILS
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NGX_STREAM_UPSTREAM_DOWN
                  |NGX_STREAM_UPSTREAM_BACKUP;

    if (cf->args->nelts == 3) {
        value = cf->args->elts;
        ltcf = ngx_stream_conf_upstream_srv_conf(uscf,
                                        ngx_stream_upstream_least_time_module);
        if (ngx_strcmp(value[2].data, "inflight") == 0) {
            ltcf->use_inflight = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return ngx_conf_set_enum_slot(cf, cmd, conf);
}

