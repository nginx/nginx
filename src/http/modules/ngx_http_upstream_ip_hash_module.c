
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_uint_t                         hash;

    u_char                             addrlen;
    u_char                            *addr;

    u_char                             tries;

    ngx_event_get_peer_pt              get_rr_peer;
} ngx_http_upstream_ip_hash_peer_data_t;


static ngx_int_t ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_ip_hash_commands[] = {

    { ngx_string("ip_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_ip_hash,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_ip_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ip_hash_module_ctx, /* module context */
    ngx_http_upstream_ip_hash_commands,    /* module directives */
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


static u_char ngx_http_upstream_ip_hash_pseudo_addr[3];


static ngx_int_t
ngx_http_upstream_init_ip_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_ip_hash_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    ngx_http_upstream_ip_hash_peer_data_t  *iphp;

    iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }

    r->upstream->peer.data = &iphp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_ip_hash_peer;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = ngx_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    i, n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = iphp->hash;

    for ( ;; ) {

        for (i = 0; i < iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }

        if (!iphp->rrp.peers->weighted) {
            p = hash % iphp->rrp.peers->number;

        } else {
            w = hash % iphp->rrp.peers->total_weight;

            for (i = 0; i < iphp->rrp.peers->number; i++) {
                w -= iphp->rrp.peers->peer[i].weight;
                if (w < 0) {
                    break;
                }
            }

            p = i;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (!(iphp->rrp.tried[n] & m)) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "get ip hash peer, hash: %ui %04XA", p, m);

            peer = &iphp->rrp.peers->peer[p];

            /* ngx_lock_mutex(iphp->rrp.peers->mutex); */

            if (!peer->down) {

                if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                    break;
                }

                if (now - peer->checked > peer->fail_timeout) {
                    peer->checked = now;
                    break;
                }
            }

            iphp->rrp.tried[n] |= m;

            /* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

            pc->tries--;
        }

        if (++iphp->tries >= 20) {
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }

    iphp->rrp.current = p;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;

    return NGX_OK;
}


static char *
ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_ip_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}
