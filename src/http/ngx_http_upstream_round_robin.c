
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t
ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_url_t                      u;
    ngx_uint_t                     i, j, n;
    ngx_http_upstream_server_t    *server;
    ngx_http_upstream_rr_peers_t  *peers;

    us->peer.init = ngx_http_upstream_init_round_robin_peer;

    if (us->servers) {
        n = 0;
        server = us->servers->elts;

        for (i = 0; i < us->servers->nelts; i++) {
            n += server[i].naddrs;
        }

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t)
                              + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peers->number = n;
        peers->name = &us->host;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peers->peer[n].socklen = server[i].addrs[j].socklen;
                peers->peer[n].name = server[i].addrs[j].name;
                peers->peer[n].weight = server[i].weight;
                peers->peer[n].current_weight = server[i].weight;
                peers->peer[n].max_fails = server[i].max_fails;
                peers->peer[n].fail_timeout = server[i].fail_timeout;
                peers->peer[n].down = server[i].down;
                n++;
            }
        }

        us->peer.data = peers;

        return NGX_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.portn = us->port;

    if (ngx_inet_resolve_host(cf, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream host \"%V\" is not found in %s:%ui",
                          u.err, &us->host, us->file_name.data, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t)
                              + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->number = n;
    peers->name = &us->host;

    n = 0;

    for (i = 0; i < u.naddrs; i++) {
        peers->peer[n].sockaddr = u.addrs[i].sockaddr;
        peers->peer[n].socklen = u.addrs[i].socklen;
        peers->peer[n].name = u.addrs[i].name;
        peers->peer[n].weight = 1;
        peers->peer[n].current_weight = 1;
        peers->peer[n].max_fails = 1;
        peers->peer[n].fail_timeout = 10;
        n++;
    }

    us->peer.data = peers;

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                         n;
    ngx_http_upstream_rr_peer_data_t  *rrp;

    rrp = r->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = rrp;
    }

    rrp->peers = us->peer.data;
    rrp->current = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
    r->upstream->peer.tries = rrp->peers->number;
#if (NGX_HTTP_SSL)
    r->upstream->peer.save_session = ngx_http_upstream_save_round_robin_peer;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                        now;
    uintptr_t                     m;
    ngx_uint_t                    i, n;
    ngx_connection_t             *c;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    now = ngx_time();

    /* ngx_lock_mutex(rrp->peers->mutex); */

    if (rrp->peers->last_cached) {

        /* cached connection */

        c = rrp->peers->cached[rrp->peers->last_cached];
        rrp->peers->last_cached--;

        /* ngx_unlock_mutex(ppr->peers->mutex); */

#if (NGX_THREADS)
        c->read->lock = c->read->own_lock;
        c->write->lock = c->write->own_lock;
#endif

        pc->connection = c;
        pc->cached = 1;

        return NGX_OK;
    }

    pc->cached = 0;
    pc->connection = NULL;

    if (rrp->peers->number == 1) {
        peer = &rrp->peers->peer[0];

    } else {

        /* there are several peers */

        if (pc->tries == rrp->peers->number) {

            /* it's a first try - get a current peer */

            for ( ;; ) {
                rrp->current = rrp->peers->current;

                n = rrp->current / (8 * sizeof(uintptr_t));
                m = 1 << rrp->current % (8 * sizeof(uintptr_t));

                if (!(rrp->tried[n] & m)) {
                    peer = &rrp->peers->peer[rrp->current];

                    if (!peer->down) {

                        if (peer->max_fails == 0
                            || peer->fails < peer->max_fails)
                        {
                            break;
                        }

                        if (now - peer->accessed > peer->fail_timeout) {
                            peer->fails = 0;
                            break;
                        }

                    } else {
                        rrp->tried[n] |= m;
                    }

                    pc->tries--;
                }

                rrp->peers->current++;

                if (rrp->peers->current >= rrp->peers->number) {
                    rrp->peers->current = 0;
                }

                if (pc->tries) {
                    continue;
                }

                goto failed;
            }

            peer->current_weight--;

            if (peer->current_weight == 0) {
                peer->current_weight = peer->weight;

                rrp->peers->current++;

                if (rrp->peers->current >= rrp->peers->number) {
                    rrp->peers->current = 0;
                }
            }

        } else {
            for ( ;; ) {
                n = rrp->current / (8 * sizeof(uintptr_t));
                m = 1 << rrp->current % (8 * sizeof(uintptr_t));

                if (!(rrp->tried[n] & m)) {

                    peer = &rrp->peers->peer[rrp->current];

                    if (!peer->down) {

                        if (peer->max_fails == 0
                            || peer->fails < peer->max_fails)
                        {
                            break;
                        }

                        if (now - peer->accessed > peer->fail_timeout) {
                            peer->fails = 0;
                            break;
                        }

                    } else {
                        rrp->tried[n] |= m;
                    }

                    pc->tries--;
                }

                rrp->current++;

                if (rrp->current >= rrp->peers->number) {
                    rrp->current = 0;
                }

                if (pc->tries) {
                    continue;
                }

                goto failed;
            }

            peer->current_weight--;

            if (peer->current_weight == 0) {
                peer->current_weight = peer->weight;

                if (rrp->current == rrp->peers->current) {
                    rrp->peers->current++;

                    if (rrp->peers->current >= rrp->peers->number) {
                        rrp->peers->current = 0;
                    }
                }
            }
        }

        rrp->tried[n] |= m;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;
#if (NGX_SSL)
    pc->ssl_session = peer->ssl_session;
#endif

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    return NGX_OK;

failed:

    /* all peers failed, mark them as live for quick recovery */

    for (i = 0; i < rrp->peers->number; i++) {
        rrp->peers->peer[i].fails = 0;
    }

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    pc->name = rrp->peers->name;

    return NGX_BUSY;
}


void
ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                       now;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    if (state == 0 && pc->tries == 0) {
        return;
    }

    /* TODO: NGX_PEER_KEEPALIVE */

    if (rrp->peers->number == 1) {
        pc->tries = 0;
        return;
    }

    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer = &rrp->peers->peer[rrp->current];

        /* ngx_lock_mutex(rrp->peers->mutex); */

        peer->fails++;
        peer->accessed = now;

        if (peer->current_weight > 1) {
            peer->current_weight /= 2;
        }

        /* ngx_unlock_mutex(rrp->peers->mutex); */
    }

    rrp->current++;

    if (rrp->current >= rrp->peers->number) {
        rrp->current = 0;
    }

    if (pc->tries) {
        pc->tries--;
    }

    /* ngx_unlock_mutex(rrp->peers->mutex); */
}


#if (NGX_HTTP_SSL)

void
ngx_http_upstream_save_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t            *ssl_session;
    ngx_http_upstream_rr_peer_t  *peer;

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    peer = &rrp->peers->peer[rrp->current];

    /* ngx_lock_mutex(rrp->peers->mutex); */
    peer->ssl_session = ssl_session;
    /* ngx_unlock_mutex(rrp->peers->mutex); */

    if (pc->ssl_session) {
        /* TODO: may block */
        ngx_ssl_free_session(pc->ssl_session);
    }
}

#endif
