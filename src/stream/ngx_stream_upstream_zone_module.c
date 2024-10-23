
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static char *ngx_stream_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_stream_upstream_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_stream_upstream_rr_peers_t *ngx_stream_upstream_zone_copy_peers(
    ngx_slab_pool_t *shpool, ngx_stream_upstream_srv_conf_t *uscf,
    ngx_stream_upstream_srv_conf_t *ouscf);
static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_zone_copy_peer(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *src);
static ngx_int_t ngx_stream_upstream_zone_preresolve(
    ngx_stream_upstream_rr_peer_t *resolve,
    ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *oresolve,
    ngx_stream_upstream_rr_peers_t *opeers);
static void ngx_stream_upstream_zone_set_single(
    ngx_stream_upstream_srv_conf_t *uscf);
static void ngx_stream_upstream_zone_remove_peer_locked(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *peer);
static ngx_int_t ngx_stream_upstream_zone_init_worker(ngx_cycle_t *cycle);
static void ngx_stream_upstream_zone_resolve_timer(ngx_event_t *event);
static void ngx_stream_upstream_zone_resolve_handler(ngx_resolver_ctx_t *ctx);


static ngx_command_t  ngx_stream_upstream_zone_commands[] = {

    { ngx_string("zone"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE12,
      ngx_stream_upstream_zone,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_zone_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_zone_module_ctx,  /* module context */
    ngx_stream_upstream_zone_commands,     /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_stream_upstream_zone_init_worker,  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_stream_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                           size;
    ngx_str_t                        *value;
    ngx_stream_upstream_srv_conf_t   *uscf;
    ngx_stream_upstream_main_conf_t  *umcf;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);
    umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);

    value = cf->args->elts;

    if (!value[1].len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = ngx_parse_size(&value[2]);

        if (size == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * ngx_pagesize)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {
        size = 0;
    }

    uscf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
                                           &ngx_stream_upstream_module);
    if (uscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    uscf->shm_zone->init = ngx_stream_upstream_init_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_upstream_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                            len;
    ngx_uint_t                        i, j;
    ngx_slab_pool_t                  *shpool;
    ngx_stream_upstream_rr_peers_t   *peers, **peersp;
    ngx_stream_upstream_srv_conf_t   *uscf, *ouscf, **uscfp, **ouscfp;
    ngx_stream_upstream_main_conf_t  *umcf, *oumcf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    umcf = shm_zone->data;
    uscfp = umcf->upstreams.elts;

    if (shm_zone->shm.exists) {
        peers = shpool->data;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->shm_zone != shm_zone) {
                continue;
            }

            uscf->peer.data = peers;
            peers = peers->zone_next;
        }

        return NGX_OK;
    }

    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    peersp = (ngx_stream_upstream_rr_peers_t **) (void *) &shpool->data;
    oumcf = data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        ouscf = NULL;

        if (oumcf) {
            ouscfp = oumcf->upstreams.elts;

            for (j = 0; j < oumcf->upstreams.nelts; j++) {

                 if (ouscfp[j]->shm_zone == NULL) {
                     continue;
                 }

                 if (ouscfp[j]->shm_zone->shm.name.len != shm_zone->shm.name.len
                     || ngx_memcmp(ouscfp[j]->shm_zone->shm.name.data,
                                   shm_zone->shm.name.data,
                                   shm_zone->shm.name.len)
                        != 0)
                 {
                     continue;
                 }

                 if (ouscfp[j]->host.len == uscf->host.len
                     && ngx_memcmp(ouscfp[j]->host.data, uscf->host.data,
                                   uscf->host.len)
                        == 0)
                 {
                     ouscf = ouscfp[j];
                     break;
                 }
            }
        }

        peers = ngx_stream_upstream_zone_copy_peers(shpool, uscf, ouscf);
        if (peers == NULL) {
            return NGX_ERROR;
        }

        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return NGX_OK;
}


static ngx_stream_upstream_rr_peers_t *
ngx_stream_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_stream_upstream_srv_conf_t *ouscf)
{
    ngx_str_t                       *name;
    ngx_uint_t                      *config;
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers, *opeers, *backup;

    opeers = (ouscf ? ouscf->peer.data : NULL);

    config = ngx_slab_calloc(shpool, sizeof(ngx_uint_t));
    if (config == NULL) {
        return NULL;
    }

    peers = ngx_slab_alloc(shpool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_stream_upstream_rr_peers_t));

    name = ngx_slab_alloc(shpool, sizeof(ngx_str_t));
    if (name == NULL) {
        return NULL;
    }

    name->data = ngx_slab_alloc(shpool, peers->name->len);
    if (name->data == NULL) {
        return NULL;
    }

    ngx_memcpy(name->data, peers->name->data, peers->name->len);
    name->len = peers->name->len;

    peers->name = name;

    peers->shpool = shpool;
    peers->config = config;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_stream_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
        (*peers->config)++;
    }

    for (peerp = &peers->resolve; *peerp; peerp = &peer->next) {
        peer = ngx_stream_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
        (*peers->config)++;
    }

    if (opeers) {

        if (ngx_stream_upstream_zone_preresolve(peers->resolve, peers,
                                                opeers->resolve, opeers)
            != NGX_OK)
        {
            return NULL;
        }
    }

    if (peers->next == NULL) {
        goto done;
    }

    backup = ngx_slab_alloc(shpool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }

    ngx_memcpy(backup, peers->next, sizeof(ngx_stream_upstream_rr_peers_t));

    backup->name = name;

    backup->shpool = shpool;
    backup->config = config;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_stream_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
        (*backup->config)++;
    }

    for (peerp = &backup->resolve; *peerp; peerp = &peer->next) {
        peer = ngx_stream_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
        (*backup->config)++;
    }

    peers->next = backup;

    if (opeers && opeers->next) {

        if (ngx_stream_upstream_zone_preresolve(peers->resolve, backup,
                                                opeers->resolve, opeers->next)
            != NGX_OK)
        {
            return NULL;
        }

        if (ngx_stream_upstream_zone_preresolve(backup->resolve, backup,
                                                opeers->next->resolve,
                                                opeers->next)
            != NGX_OK)
        {
            return NULL;
        }
    }

done:

    uscf->peer.data = peers;

    ngx_stream_upstream_zone_set_single(uscf);

    return peers;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_zone_copy_peer(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *src)
{
    ngx_slab_pool_t                *pool;
    ngx_stream_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = ngx_slab_calloc_locked(pool, sizeof(ngx_stream_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        ngx_memcpy(dst, src, sizeof(ngx_stream_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
        dst->host = NULL;
    }

    dst->sockaddr = ngx_slab_calloc_locked(pool, sizeof(ngx_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = ngx_slab_calloc_locked(pool, NGX_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }

    if (src) {
        ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
        ngx_memcpy(dst->name.data, src->name.data, src->name.len);

        dst->server.data = ngx_slab_alloc_locked(pool, src->server.len);
        if (dst->server.data == NULL) {
            goto failed;
        }

        ngx_memcpy(dst->server.data, src->server.data, src->server.len);

        if (src->host) {
            dst->host = ngx_slab_calloc_locked(pool,
                                            sizeof(ngx_stream_upstream_host_t));
            if (dst->host == NULL) {
                goto failed;
            }

            dst->host->name.data = ngx_slab_alloc_locked(pool,
                                                         src->host->name.len);
            if (dst->host->name.data == NULL) {
                goto failed;
            }

            dst->host->peers = peers;
            dst->host->peer = dst;

            dst->host->name.len = src->host->name.len;
            ngx_memcpy(dst->host->name.data, src->host->name.data,
                       src->host->name.len);

            if (src->host->service.len) {
                dst->host->service.data = ngx_slab_alloc_locked(pool,
                                                        src->host->service.len);
                if (dst->host->service.data == NULL) {
                    goto failed;
                }

                dst->host->service.len = src->host->service.len;
                ngx_memcpy(dst->host->service.data, src->host->service.data,
                           src->host->service.len);
            }
        }
    }

    return dst;

failed:

    if (dst->host) {
        if (dst->host->name.data) {
            ngx_slab_free_locked(pool, dst->host->name.data);
        }

        ngx_slab_free_locked(pool, dst->host);
    }

    if (dst->server.data) {
        ngx_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        ngx_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        ngx_slab_free_locked(pool, dst->sockaddr);
    }

    ngx_slab_free_locked(pool, dst);

    return NULL;
}


static ngx_int_t
ngx_stream_upstream_zone_preresolve(ngx_stream_upstream_rr_peer_t *resolve,
    ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *oresolve,
    ngx_stream_upstream_rr_peers_t *opeers)
{
    in_port_t                       port;
    ngx_str_t                      *server;
    ngx_stream_upstream_host_t     *host;
    ngx_stream_upstream_rr_peer_t  *peer, *template, *opeer, **peerp;

    if (resolve == NULL || oresolve == NULL) {
        return NGX_OK;
    }

    for (peerp = &peers->peer; *peerp; peerp = &(*peerp)->next) {
        /* void */
    }

    ngx_stream_upstream_rr_peers_rlock(opeers);

    for (template = resolve; template; template = template->next) {
        for (opeer = oresolve; opeer; opeer = opeer->next) {

            if (opeer->host->name.len != template->host->name.len
                || ngx_memcmp(opeer->host->name.data,
                              template->host->name.data,
                              template->host->name.len)
                   != 0)
            {
                continue;
            }

            if (opeer->host->service.len != template->host->service.len
                || ngx_memcmp(opeer->host->service.data,
                              template->host->service.data,
                              template->host->service.len)
                   != 0)
            {
                continue;
            }

            host = opeer->host;

            for (opeer = opeers->peer; opeer; opeer = opeer->next) {

                if (opeer->host != host) {
                    continue;
                }

                peer = ngx_stream_upstream_zone_copy_peer(peers, NULL);
                if (peer == NULL) {
                    ngx_stream_upstream_rr_peers_unlock(opeers);
                    return NGX_ERROR;
                }

                ngx_memcpy(peer->sockaddr, opeer->sockaddr, opeer->socklen);

                if (template->host->service.len == 0) {
                    port = ngx_inet_get_port(template->sockaddr);
                    ngx_inet_set_port(peer->sockaddr, port);
                }

                peer->socklen = opeer->socklen;

                peer->name.len = ngx_sock_ntop(peer->sockaddr, peer->socklen,
                                               peer->name.data,
                                               NGX_SOCKADDR_STRLEN, 1);

                peer->host = template->host;

                template->host->valid = host->valid;

                server = template->host->service.len ? &opeer->server
                                                     : &template->server;

                peer->server.data = ngx_slab_alloc(peers->shpool, server->len);
                if (peer->server.data == NULL) {
                    ngx_stream_upstream_rr_peers_unlock(opeers);
                    return NGX_ERROR;
                }

                ngx_memcpy(peer->server.data, server->data, server->len);
                peer->server.len = server->len;

                if (host->service.len == 0) {
                    peer->weight = template->weight;

                } else {
                    peer->weight = (template->weight != 1 ? template->weight
                                                          : opeer->weight);
                }

                peer->effective_weight = peer->weight;
                peer->max_conns = template->max_conns;
                peer->max_fails = template->max_fails;
                peer->fail_timeout = template->fail_timeout;
                peer->down = template->down;

                (*peers->config)++;

                *peerp = peer;
                peerp = &peer->next;

                peers->number++;
                peers->tries += (peer->down == 0);
                peers->total_weight += peer->weight;
                peers->weighted = (peers->total_weight != peers->number);
            }

            break;
        }
    }

    ngx_stream_upstream_rr_peers_unlock(opeers);
    return NGX_OK;
}


static void
ngx_stream_upstream_zone_set_single(ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_stream_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    if (peers->number == 1
        && (peers->next == NULL || peers->next->number == 0))
    {
        peers->single = 1;

    } else {
        peers->single = 0;
    }
}


static void
ngx_stream_upstream_zone_remove_peer_locked(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *peer)
{
    peers->total_weight -= peer->weight;
    peers->number--;
    peers->tries -= (peer->down == 0);
    (*peers->config)++;
    peers->weighted = (peers->total_weight != peers->number);

    ngx_stream_upstream_rr_peer_free(peers, peer);
}


static ngx_int_t
ngx_stream_upstream_zone_init_worker(ngx_cycle_t *cycle)
{
    time_t                            now;
    ngx_msec_t                        timer;
    ngx_uint_t                        i;
    ngx_event_t                      *event;
    ngx_stream_upstream_rr_peer_t    *peer;
    ngx_stream_upstream_rr_peers_t   *peers;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    now = ngx_time();
    umcf = ngx_stream_cycle_get_module_main_conf(cycle,
                                                 ngx_stream_upstream_module);

    if (umcf == NULL) {
        return NGX_OK;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        if (uscf->shm_zone == NULL) {
            continue;
        }

        peers = uscf->peer.data;

        do {
            ngx_stream_upstream_rr_peers_wlock(peers);

            for (peer = peers->resolve; peer; peer = peer->next) {

                if (peer->host->worker != ngx_worker) {
                    continue;
                }

                event = &peer->host->event;
                ngx_memzero(event, sizeof(ngx_event_t));

                event->data = uscf;
                event->handler = ngx_stream_upstream_zone_resolve_timer;
                event->log = cycle->log;
                event->cancelable = 1;

                timer = (peer->host->valid > now)
                        ? (ngx_msec_t) 1000 * (peer->host->valid - now) : 1;

                ngx_add_timer(event, timer);
            }

            ngx_stream_upstream_rr_peers_unlock(peers);

            peers = peers->next;

        } while (peers);
    }

    return NGX_OK;
}


static void
ngx_stream_upstream_zone_resolve_timer(ngx_event_t *event)
{
    ngx_resolver_ctx_t              *ctx;
    ngx_stream_upstream_host_t      *host;
    ngx_stream_upstream_srv_conf_t  *uscf;

    host = (ngx_stream_upstream_host_t *) event;
    uscf = event->data;

    ctx = ngx_resolve_start(uscf->resolver, NULL);
    if (ctx == NULL) {
        goto retry;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "no resolver defined to resolve %V", &host->name);
        return;
    }

    ctx->name = host->name;
    ctx->handler = ngx_stream_upstream_zone_resolve_handler;
    ctx->data = host;
    ctx->timeout = uscf->resolver_timeout;
    ctx->service = host->service;
    ctx->cancelable = 1;

    if (ngx_resolve_name(ctx) == NGX_OK) {
        return;
    }

retry:

    ngx_add_timer(event, ngx_max(uscf->resolver_timeout, 1000));
}


#define ngx_stream_upstream_zone_addr_marked(addr)                            \
    ((uintptr_t) (addr)->sockaddr & 1)

#define ngx_stream_upstream_zone_mark_addr(addr)                              \
    (addr)->sockaddr = (struct sockaddr *) ((uintptr_t) (addr)->sockaddr | 1)

#define ngx_stream_upstream_zone_unmark_addr(addr)                            \
    (addr)->sockaddr =                                                        \
        (struct sockaddr *) ((uintptr_t) (addr)->sockaddr & ~((uintptr_t) 1))

static void
ngx_stream_upstream_zone_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    time_t                           now;
    u_short                          min_priority;
    in_port_t                        port;
    ngx_str_t                       *server;
    ngx_msec_t                       timer;
    ngx_uint_t                       i, j, backup, addr_backup;
    ngx_event_t                     *event;
    ngx_resolver_addr_t             *addr;
    ngx_resolver_srv_name_t         *srv;
    ngx_stream_upstream_host_t      *host;
    ngx_stream_upstream_rr_peer_t   *peer, *template, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers;
    ngx_stream_upstream_srv_conf_t  *uscf;

    host = ctx->data;
    event = &host->event;
    uscf = event->data;
    peers = host->peers;
    template = host->peer;

    ngx_stream_upstream_rr_peers_wlock(peers);

    now = ngx_time();

    for (i = 0; i < ctx->nsrvs; i++) {
        srv = &ctx->srvs[i];

        if (srv->state) {
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "%V could not be resolved (%i: %s) "
                          "while resolving service %V of %V",
                          &srv->name, srv->state,
                          ngx_resolver_strerror(srv->state), &ctx->service,
                          &ctx->name);
        }
    }

    if (ctx->state) {
        if (ctx->service.len) {
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "service %V of %V could not be resolved (%i: %s)",
                          &ctx->service, &ctx->name, ctx->state,
                          ngx_resolver_strerror(ctx->state));

        } else {
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "%V could not be resolved (%i: %s)",
                          &ctx->name, ctx->state,
                          ngx_resolver_strerror(ctx->state));
        }

        if (ctx->state != NGX_RESOLVE_NXDOMAIN) {
            ngx_stream_upstream_rr_peers_unlock(peers);

            ngx_resolve_name_done(ctx);

            ngx_add_timer(event, ngx_max(uscf->resolver_timeout, 1000));
            return;
        }

        /* NGX_RESOLVE_NXDOMAIN */

        ctx->naddrs = 0;
    }

    backup = 0;
    min_priority = 65535;

    for (i = 0; i < ctx->naddrs; i++) {
        min_priority = ngx_min(ctx->addrs[i].priority, min_priority);
    }

#if (NGX_DEBUG)
    {
    u_char  text[NGX_SOCKADDR_STRLEN];
    size_t  len;

    for (i = 0; i < ctx->naddrs; i++) {
        len = ngx_sock_ntop(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                            text, NGX_SOCKADDR_STRLEN, 1);

        ngx_log_debug7(NGX_LOG_DEBUG_STREAM, event->log, 0,
                       "name %V was resolved to %*s "
                       "s:\"%V\" n:\"%V\" w:%d %s",
                       &host->name, len, text, &host->service,
                       &ctx->addrs[i].name, ctx->addrs[i].weight,
                       ctx->addrs[i].priority != min_priority ? "backup" : "");
    }
    }
#endif

again:

    for (peerp = &peers->peer; *peerp; /* void */ ) {
        peer = *peerp;

        if (peer->host != host) {
            goto next;
        }

        for (j = 0; j < ctx->naddrs; j++) {

            addr = &ctx->addrs[j];

            addr_backup = (addr->priority != min_priority);
            if (addr_backup != backup) {
                continue;
            }

            if (ngx_stream_upstream_zone_addr_marked(addr)) {
                continue;
            }

            if (ngx_cmp_sockaddr(peer->sockaddr, peer->socklen,
                                 addr->sockaddr, addr->socklen,
                                 host->service.len != 0)
                != NGX_OK)
            {
                continue;
            }

            if (host->service.len) {
                if (addr->name.len != peer->server.len
                    || ngx_strncmp(addr->name.data, peer->server.data,
                                   addr->name.len))
                {
                    continue;
                }

                if (template->weight == 1 && addr->weight != peer->weight) {
                    continue;
                }
            }

            ngx_stream_upstream_zone_mark_addr(addr);

            goto next;
        }

        *peerp = peer->next;
        ngx_stream_upstream_zone_remove_peer_locked(peers, peer);

        ngx_stream_upstream_zone_set_single(uscf);

        continue;

    next:

        peerp = &peer->next;
    }

    for (i = 0; i < ctx->naddrs; i++) {

        addr = &ctx->addrs[i];

        addr_backup = (addr->priority != min_priority);
        if (addr_backup != backup) {
            continue;
        }

        if (ngx_stream_upstream_zone_addr_marked(addr)) {
            ngx_stream_upstream_zone_unmark_addr(addr);
            continue;
        }

        ngx_shmtx_lock(&peers->shpool->mutex);
        peer = ngx_stream_upstream_zone_copy_peer(peers, NULL);
        ngx_shmtx_unlock(&peers->shpool->mutex);

        if (peer == NULL) {
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "cannot add new server to upstream \"%V\", "
                          "memory exhausted", peers->name);
            goto done;
        }

        ngx_memcpy(peer->sockaddr, addr->sockaddr, addr->socklen);

        if (host->service.len == 0) {
            port = ngx_inet_get_port(template->sockaddr);
            ngx_inet_set_port(peer->sockaddr, port);
        }

        peer->socklen = addr->socklen;

        peer->name.len = ngx_sock_ntop(peer->sockaddr, peer->socklen,
                                       peer->name.data, NGX_SOCKADDR_STRLEN, 1);

        peer->host = template->host;

        server = host->service.len ? &addr->name : &template->server;

        peer->server.data = ngx_slab_alloc(peers->shpool, server->len);
        if (peer->server.data == NULL) {
            ngx_stream_upstream_rr_peer_free(peers, peer);

            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "cannot add new server to upstream \"%V\", "
                          "memory exhausted", peers->name);
            goto done;
        }

        peer->server.len = server->len;
        ngx_memcpy(peer->server.data, server->data, server->len);

        if (host->service.len == 0) {
            peer->weight = template->weight;

        } else {
            peer->weight = (template->weight != 1 ? template->weight
                                                  : addr->weight);
        }

        peer->effective_weight = peer->weight;
        peer->max_conns = template->max_conns;
        peer->max_fails = template->max_fails;
        peer->fail_timeout = template->fail_timeout;
        peer->down = template->down;

        *peerp = peer;
        peerp = &peer->next;

        peers->number++;
        peers->tries += (peer->down == 0);
        peers->total_weight += peer->weight;
        peers->weighted = (peers->total_weight != peers->number);
        (*peers->config)++;

        ngx_stream_upstream_zone_set_single(uscf);
    }

    if (host->service.len && peers->next) {
        ngx_stream_upstream_rr_peers_unlock(peers);

        peers = peers->next;
        backup = 1;

        ngx_stream_upstream_rr_peers_wlock(peers);

        goto again;
    }

done:

    host->valid = ctx->valid;

    ngx_stream_upstream_rr_peers_unlock(peers);

    while (++i < ctx->naddrs) {
        ngx_stream_upstream_zone_unmark_addr(&ctx->addrs[i]);
    }

    timer = (ngx_msec_t) 1000 * (ctx->valid > now ? ctx->valid - now + 1 : 1);

    ngx_resolve_name_done(ctx);

    ngx_add_timer(event, timer);
}
