
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define ngx_stream_upstream_tries(p) ((p)->tries                              \
                                      + ((p)->next ? (p)->next->tries : 0))


static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_get_peer(
    ngx_stream_upstream_rr_peer_data_t *rrp);
static void ngx_stream_upstream_notify_round_robin_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

#if (NGX_STREAM_SSL)

static ngx_int_t ngx_stream_upstream_set_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_stream_upstream_save_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);
static ngx_int_t ngx_stream_upstream_empty_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_stream_upstream_empty_save_session(ngx_peer_connection_t *pc,
    void *data);

#endif


ngx_int_t
ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_url_t                        u;
    ngx_uint_t                       i, j, n, r, w, t;
    ngx_stream_upstream_server_t    *server;
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers, *backup;
#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_uint_t                       resolve;
    ngx_stream_core_srv_conf_t      *cscf;
    ngx_stream_upstream_rr_peer_t  **rpeerp;
#endif

    us->peer.init = ngx_stream_upstream_init_round_robin_peer;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;
        r = 0;
        w = 0;
        t = 0;

#if (NGX_STREAM_UPSTREAM_ZONE)
        resolve = 0;
#endif

        for (i = 0; i < us->servers->nelts; i++) {

#if (NGX_STREAM_UPSTREAM_ZONE)
            if (server[i].host.len) {
                resolve = 1;
            }
#endif

            if (server[i].backup) {
                continue;
            }

#if (NGX_STREAM_UPSTREAM_ZONE)
            if (server[i].host.len) {
                r++;
                continue;
            }
#endif

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

#if (NGX_STREAM_UPSTREAM_ZONE)
        if (us->shm_zone) {

            if (resolve && !(us->flags & NGX_STREAM_UPSTREAM_MODIFY)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "load balancing method does not support"
                              " resolving names at run time in"
                              " upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

            cscf = ngx_stream_conf_get_module_srv_conf(cf,
                                                       ngx_stream_core_module);

            if (us->resolver == NULL) {
                us->resolver = cscf->resolver;
            }

            /*
             * Without "resolver_timeout" in stream{} the merged value is unset.
             */
            ngx_conf_merge_msec_value(us->resolver_timeout,
                                      cscf->resolver_timeout, 30000);

            if (resolve
                && (us->resolver == NULL
                    || us->resolver->connections.nelts == 0))
            {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "no resolver defined to resolve names"
                              " at run time in upstream \"%V\" in %s:%ui",
                              &us->host, us->file_name, us->line);
                return NGX_ERROR;
            }

        } else if (resolve) {

            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "resolving names at run time requires"
                          " upstream \"%V\" in %s:%ui"
                          " to be in shared memory",
                          &us->host, us->file_name, us->line);
            return NGX_ERROR;
        }
#endif

        if (n + r == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no servers in upstream \"%V\" in %s:%ui",
                          &us->host, us->file_name, us->line);
            return NGX_ERROR;
        }

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t)
                                     * (n + r));
        if (peer == NULL) {
            return NGX_ERROR;
        }

        peers->single = (n == 1);
        peers->number = n;
        peers->weighted = (w != n);
        peers->total_weight = w;
        peers->tries = t;
        peers->name = &us->host;

        n = 0;
        peerp = &peers->peer;

#if (NGX_STREAM_UPSTREAM_ZONE)
        rpeerp = &peers->resolve;
#endif

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

#if (NGX_STREAM_UPSTREAM_ZONE)
            if (server[i].host.len) {

                peer[n].host = ngx_pcalloc(cf->pool,
                                           sizeof(ngx_stream_upstream_host_t));
                if (peer[n].host == NULL) {
                    return NGX_ERROR;
                }

                peer[n].host->name = server[i].host;
                peer[n].host->service = server[i].service;

                peer[n].sockaddr = server[i].addrs[0].sockaddr;
                peer[n].socklen = server[i].addrs[0].socklen;
                peer[n].name = server[i].addrs[0].name;
                peer[n].weight = server[i].weight;
                /* Initialize to 1 instead of server[i].weight for randomness */
                peer[n].effective_weight = 1;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
                *rpeerp = &peer[n];
                rpeerp = &peer[n].next;
                n++;

                continue;
            }
#endif

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                /* Initialize to 1 instead of server[i].weight for randomness */
                peer[n].effective_weight = 1;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        us->peer.data = peers;

        /* backup servers */

        n = 0;
        r = 0;
        w = 0;
        t = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

#if (NGX_STREAM_UPSTREAM_ZONE)
            if (server[i].host.len) {
                r++;
                continue;
            }
#endif

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

        if (n == 0
#if (NGX_STREAM_UPSTREAM_ZONE)
            && !resolve
#endif
        ) {
            return NGX_OK;
        }

        if (n + r == 0 && !(us->flags & NGX_STREAM_UPSTREAM_BACKUP)) {
            return NGX_OK;
        }

        backup = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t)
                                     * (n + r));
        if (peer == NULL) {
            return NGX_ERROR;
        }

        if (n > 0) {
            peers->single = 0;
        }

        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->tries = t;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

#if (NGX_STREAM_UPSTREAM_ZONE)
        rpeerp = &backup->resolve;
#endif

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

#if (NGX_STREAM_UPSTREAM_ZONE)
            if (server[i].host.len) {

                peer[n].host = ngx_pcalloc(cf->pool,
                                           sizeof(ngx_stream_upstream_host_t));
                if (peer[n].host == NULL) {
                    return NGX_ERROR;
                }

                peer[n].host->name = server[i].host;
                peer[n].host->service = server[i].service;

                peer[n].sockaddr = server[i].addrs[0].sockaddr;
                peer[n].socklen = server[i].addrs[0].socklen;
                peer[n].name = server[i].addrs[0].name;
                peer[n].weight = server[i].weight;
                /* Initialize to 1 instead of server[i].weight for randomness */
                peer[n].effective_weight = 1;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
                *rpeerp = &peer[n];
                rpeerp = &peer[n].next;
                n++;

                continue;
            }
#endif

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                /* Initialize to 1 instead of server[i].weight for randomness */
                peer[n].effective_weight = 1;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        peers->next = backup;

        return NGX_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.port = us->port;

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->tries = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
        peer[i].current_weight = 0;
        peer[i].max_conns = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}


ngx_int_t
ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_uint_t                           n;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(s->connection->pool,
                         sizeof(ngx_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    rrp->peers = us->peer.data;
    rrp->current = NULL;

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    rrp->config = rrp->peers->config ? *rrp->peers->config : 0;
#endif

    n = rrp->peers->number;

    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

    s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);

    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

    if (n <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
    s->upstream->peer.notify = ngx_stream_upstream_notify_round_robin_peer;

#if (NGX_STREAM_SSL)
    s->upstream->peer.set_session =
                             ngx_stream_upstream_set_round_robin_peer_session;
    s->upstream->peer.save_session =
                             ngx_stream_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_stream_upstream_create_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_resolved_t *ur)
{
    u_char                              *p;
    size_t                               len;
    socklen_t                            socklen;
    ngx_uint_t                           i, n;
    struct sockaddr                     *sockaddr;
    ngx_stream_upstream_rr_peer_t       *peer, **peerp;
    ngx_stream_upstream_rr_peers_t      *peers;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(s->connection->pool,
                         sizeof(ngx_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    peers = ngx_pcalloc(s->connection->pool,
                        sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(s->connection->pool,
                       sizeof(ngx_stream_upstream_rr_peer_t) * ur->naddrs);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (ur->naddrs == 1);
    peers->number = ur->naddrs;
    peers->tries = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        peer[0].sockaddr = ur->sockaddr;
        peer[0].socklen = ur->socklen;
        peer[0].name = ur->name;
        peer[0].weight = 1;
        peer[0].effective_weight = 1;
        peer[0].current_weight = 0;
        peer[0].max_conns = 0;
        peer[0].max_fails = 1;
        peer[0].fail_timeout = 10;
        peers->peer = peer;

    } else {
        peerp = &peers->peer;

        for (i = 0; i < ur->naddrs; i++) {

            socklen = ur->addrs[i].socklen;

            sockaddr = ngx_palloc(s->connection->pool, socklen);
            if (sockaddr == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);
            ngx_inet_set_port(sockaddr, ur->port);

            p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);

            peer[i].sockaddr = sockaddr;
            peer[i].socklen = socklen;
            peer[i].name.len = len;
            peer[i].name.data = p;
            peer[i].weight = 1;
            peer[i].effective_weight = 1;
            peer[i].current_weight = 0;
            peer[i].max_conns = 0;
            peer[i].max_fails = 1;
            peer[i].fail_timeout = 10;
            *peerp = &peer[i];
            peerp = &peer[i].next;
        }
    }

    rrp->peers = peers;
    rrp->current = NULL;
    rrp->config = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
    s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);
#if (NGX_STREAM_SSL)
    s->upstream->peer.set_session = ngx_stream_upstream_empty_set_session;
    s->upstream->peer.save_session = ngx_stream_upstream_empty_save_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t *rrp = data;

    ngx_int_t                        rc;
    ngx_uint_t                       i, n;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->connection = NULL;

    peers = rrp->peers;
    ngx_stream_upstream_rr_peers_wlock(peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (peers->config && rrp->config != *peers->config) {
        goto busy;
    }
#endif

    if (peers->single) {
        peer = peers->peer;

        if (peer->down) {
            goto failed;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto failed;
        }

        rrp->current = peer;
        ngx_stream_upstream_rr_peer_ref(peers, peer);

    } else {

        /* there are several peers */

        peer = ngx_stream_upstream_get_peer(rrp);

        if (peer == NULL) {
            goto failed;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get rr peer, current: %p %i",
                       peer, peer->current_weight);
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_round_robin_peer(pc, rrp);

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


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_get_peer(ngx_stream_upstream_rr_peer_data_t *rrp)
{
    time_t                          now;
    uintptr_t                       m;
    ngx_int_t                       total;
    ngx_uint_t                      i, n, p;
    ngx_stream_upstream_rr_peer_t  *peer, *best;

    now = ngx_time();

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    p = 0;
#endif

    for (peer = rrp->peers->peer, i = 0;
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

        peer->current_weight += peer->effective_weight;
        total += peer->effective_weight;

        if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }

        /*
         * Introduce randomness to solve the herd effect in cluster deployment
         * When two peers have equal current weights, use random number to decide which one to choose
         */
        if (best == NULL
            || peer->current_weight > best->current_weight
            || (peer->current_weight == best->current_weight
                && ngx_random() % 2))
        {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
        return NULL;
    }

    rrp->current = best;
    ngx_stream_upstream_rr_peer_ref(rrp->peers, best);

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    return best;
}


void
ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    time_t                          now;
    ngx_stream_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    peer = rrp->current;

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);
    ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

    if (rrp->peers->single) {

        if (peer->fails) {
            peer->fails = 0;
        }

        peer->conns--;

        if (ngx_stream_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
            ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
        }

        ngx_stream_upstream_rr_peers_unlock(rrp->peers);

        pc->tries = 0;
        return;
    }

    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer->fails++;
        peer->accessed = now;
        peer->checked = now;

        if (peer->max_fails) {
            peer->effective_weight -= peer->weight / peer->max_fails;

            if (peer->fails >= peer->max_fails) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                              "upstream server temporarily disabled");
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "free rr peer failed: %p %i",
                       peer, peer->effective_weight);

        if (peer->effective_weight < 0) {
            peer->effective_weight = 0;
        }

    } else {

        /* mark peer live if check passed */

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }
    }

    peer->conns--;

    if (ngx_stream_upstream_rr_peer_unref(rrp->peers, peer) == NGX_OK) {
        ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
    }

    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

    if (pc->tries) {
        pc->tries--;
    }
}


static void
ngx_stream_upstream_notify_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_stream_upstream_rr_peer_t  *peer;

    peer = rrp->current;

    if (type == NGX_STREAM_UPSTREAM_NOTIFY_CONNECT
        && pc->connection->type == SOCK_STREAM)
    {
        ngx_stream_upstream_rr_peers_rlock(rrp->peers);
        ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }

        ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
        ngx_stream_upstream_rr_peers_unlock(rrp->peers);
    }
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                        rc;
    ngx_ssl_session_t               *ssl_session;
    ngx_stream_upstream_rr_peer_t   *peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    int                              len;
    const u_char                    *p;
    ngx_stream_upstream_rr_peers_t  *peers;
#endif

    peer = rrp->current;

#if (NGX_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {
        ngx_stream_upstream_rr_peers_rlock(peers);
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (peer->ssl_session == NULL) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            ngx_stream_upstream_rr_peers_unlock(peers);
            return NGX_OK;
        }

        len = peer->ssl_session_len;

        ngx_memcpy(ngx_ssl_session_buffer, peer->ssl_session, len);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        p = ngx_ssl_session_buffer;
        ssl_session = d2i_SSL_SESSION(NULL, &p, len);

        rc = ngx_ssl_set_session(pc->connection, ssl_session);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "set session: %p", ssl_session);

        ngx_ssl_free_session(ssl_session);

        return rc;
    }
#endif

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "set session: %p", ssl_session);

    return rc;
}


static void
ngx_stream_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t               *old_ssl_session, *ssl_session;
    ngx_stream_upstream_rr_peer_t   *peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    int                              len;
    u_char                          *p;
    ngx_stream_upstream_rr_peers_t  *peers;
#endif

#if (NGX_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {

        ssl_session = ngx_ssl_get0_session(pc->connection);

        if (ssl_session == NULL) {
            return;
        }

        len = i2d_SSL_SESSION(ssl_session, NULL);

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "save session: %p:%d", ssl_session, len);

        /* do not cache too big session */

        if (len > NGX_SSL_MAX_SESSION_SIZE) {
            return;
        }

        p = ngx_ssl_session_buffer;
        (void) i2d_SSL_SESSION(ssl_session, &p);

        peer = rrp->current;

        ngx_stream_upstream_rr_peers_rlock(peers);
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (len > peer->ssl_session_len) {
            ngx_shmtx_lock(&peers->shpool->mutex);

            if (peer->ssl_session) {
                ngx_slab_free_locked(peers->shpool, peer->ssl_session);
            }

            peer->ssl_session = ngx_slab_alloc_locked(peers->shpool, len);

            ngx_shmtx_unlock(&peers->shpool->mutex);

            if (peer->ssl_session == NULL) {
                peer->ssl_session_len = 0;

                ngx_stream_upstream_rr_peer_unlock(peers, peer);
                ngx_stream_upstream_rr_peers_unlock(peers);
                return;
            }

            peer->ssl_session_len = len;
        }

        ngx_memcpy(peer->ssl_session, ngx_ssl_session_buffer, len);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        return;
    }
#endif

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "save session: %p", ssl_session);

    peer = rrp->current;

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    if (old_ssl_session) {

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "old session: %p", old_ssl_session);

        ngx_ssl_free_session(old_ssl_session);
    }
}


static ngx_int_t
ngx_stream_upstream_empty_set_session(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_stream_upstream_empty_save_session(ngx_peer_connection_t *pc, void *data)
{
    return;
}

#endif
