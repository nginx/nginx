
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    uint32_t                              hash;
    ngx_str_t                            *server;
} ngx_stream_upstream_chash_point_t;


typedef struct {
    ngx_uint_t                            number;
    ngx_stream_upstream_chash_point_t     point[1];
} ngx_stream_upstream_chash_points_t;


typedef struct {
#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_uint_t                            config;
#endif
    ngx_stream_complex_value_t            key;
    ngx_stream_upstream_chash_points_t   *points;
} ngx_stream_upstream_hash_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    ngx_stream_upstream_rr_peer_data_t    rrp;
    ngx_stream_upstream_hash_srv_conf_t  *conf;
    ngx_str_t                             key;
    ngx_uint_t                            tries;
    ngx_uint_t                            rehash;
    uint32_t                              hash;
    ngx_event_get_peer_pt                 get_rr_peer;
} ngx_stream_upstream_hash_peer_data_t;


static ngx_int_t ngx_stream_upstream_init_hash(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_init_hash_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_hash_peer(ngx_peer_connection_t *pc,
    void *data);

static ngx_int_t ngx_stream_upstream_init_chash(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_update_chash(ngx_pool_t *pool,
    ngx_stream_upstream_srv_conf_t *us);
static int ngx_libc_cdecl
    ngx_stream_upstream_chash_cmp_points(const void *one, const void *two);
static ngx_uint_t ngx_stream_upstream_find_chash_point(
    ngx_stream_upstream_chash_points_t *points, uint32_t hash);
static ngx_int_t ngx_stream_upstream_init_chash_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_chash_peer(ngx_peer_connection_t *pc,
    void *data);

static void *ngx_stream_upstream_hash_create_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_upstream_hash_commands[] = {

    { ngx_string("hash"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE12,
      ngx_stream_upstream_hash,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_upstream_hash_create_conf,  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_hash_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_hash_module_ctx,  /* module context */
    ngx_stream_upstream_hash_commands,     /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
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
ngx_stream_upstream_init_hash(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_hash_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_hash_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_hash_srv_conf_t   *hcf;
    ngx_stream_upstream_hash_peer_data_t  *hp;

    hp = ngx_palloc(s->connection->pool,
                    sizeof(ngx_stream_upstream_hash_peer_data_t));
    if (hp == NULL) {
        return NGX_ERROR;
    }

    s->upstream->peer.data = &hp->rrp;

    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_stream_upstream_get_hash_peer;

    hcf = ngx_stream_conf_upstream_srv_conf(us,
                                            ngx_stream_upstream_hash_module);

    if (ngx_stream_complex_value(s, &hcf->key, &hp->key) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream hash key:\"%V\"", &hp->key);

    hp->conf = hcf;
    hp->tries = 0;
    hp->rehash = 0;
    hp->hash = 0;
    hp->get_rr_peer = ngx_stream_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_hash_peer_data_t *hp = data;

    time_t                          now;
    u_char                          buf[NGX_INT_T_LEN];
    size_t                          size;
    uint32_t                        hash;
    ngx_int_t                       w;
    uintptr_t                       m;
    ngx_uint_t                      n, p;
    ngx_stream_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get hash peer, try: %ui", pc->tries);

    ngx_stream_upstream_rr_peers_rlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->number < 2 || hp->key.len == 0) {
        ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (hp->rrp.peers->config && hp->rrp.config != *hp->rrp.peers->config) {
        ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }
#endif

    now = ngx_time();

    pc->connection = NULL;

    for ( ;; ) {

        /*
         * Hash expression is compatible with Cache::Memcached:
         * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
         * with REHASH omitted at the first iteration.
         */

        ngx_crc32_init(hash);

        if (hp->rehash > 0) {
            size = ngx_sprintf(buf, "%ui", hp->rehash) - buf;
            ngx_crc32_update(&hash, buf, size);
        }

        ngx_crc32_update(&hash, hp->key.data, hp->key.len);
        ngx_crc32_final(hash);

        hash = (hash >> 16) & 0x7fff;

        hp->hash += hash;
        hp->rehash++;

        w = hp->hash % hp->rrp.peers->total_weight;
        peer = hp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (hp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_stream_upstream_rr_peer_lock(hp->rrp.peers, peer);

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get hash peer, value:%uD, peer:%ui", hp->hash, p);

        if (peer->down) {
            ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        if (++hp->tries > 20) {
            ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

    hp->rrp.current = peer;
    ngx_stream_upstream_rr_peer_ref(hp->rrp.peers, peer);

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
    ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);

    hp->rrp.tried[n] |= m;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_chash(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_chash_peer;

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (us->shm_zone) {
        return NGX_OK;
    }
#endif

    return ngx_stream_upstream_update_chash(cf->pool, us);
}


static ngx_int_t
ngx_stream_upstream_update_chash(ngx_pool_t *pool,
    ngx_stream_upstream_srv_conf_t *us)
{
    u_char                               *host, *port, c;
    size_t                                host_len, port_len, size;
    uint32_t                              hash, base_hash;
    ngx_str_t                            *server;
    ngx_uint_t                            npoints, i, j;
    ngx_stream_upstream_rr_peer_t        *peer;
    ngx_stream_upstream_rr_peers_t       *peers;
    ngx_stream_upstream_chash_points_t   *points;
    ngx_stream_upstream_hash_srv_conf_t  *hcf;
    union {
        uint32_t                          value;
        u_char                            byte[4];
    } prev_hash;

    hcf = ngx_stream_conf_upstream_srv_conf(us,
                                            ngx_stream_upstream_hash_module);

    if (hcf->points) {
        ngx_free(hcf->points);
        hcf->points = NULL;
    }

    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    size = sizeof(ngx_stream_upstream_chash_points_t)
           - sizeof(ngx_stream_upstream_chash_point_t)
           + sizeof(ngx_stream_upstream_chash_point_t) * npoints;

    points = pool ? ngx_palloc(pool, size) : ngx_alloc(size, ngx_cycle->log);
    if (points == NULL) {
        return NGX_ERROR;
    }

    points->number = 0;

    if (npoints == 0) {
        hcf->points = points;
        return NGX_OK;
    }

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && ngx_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        ngx_crc32_init(base_hash);
        ngx_crc32_update(&base_hash, host, host_len);
        ngx_crc32_update(&base_hash, (u_char *) "", 1);
        ngx_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            ngx_crc32_update(&hash, prev_hash.byte, 4);
            ngx_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (NGX_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    ngx_qsort(points->point,
              points->number,
              sizeof(ngx_stream_upstream_chash_point_t),
              ngx_stream_upstream_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    hcf->points = points;

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_stream_upstream_chash_cmp_points(const void *one, const void *two)
{
    ngx_stream_upstream_chash_point_t *first =
                                     (ngx_stream_upstream_chash_point_t *) one;
    ngx_stream_upstream_chash_point_t *second =
                                     (ngx_stream_upstream_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


static ngx_uint_t
ngx_stream_upstream_find_chash_point(ngx_stream_upstream_chash_points_t *points,
    uint32_t hash)
{
    ngx_uint_t                          i, j, k;
    ngx_stream_upstream_chash_point_t  *point;

    /* find first point >= hash */

    point = &points->point[0];

    i = 0;
    j = points->number;

    while (i < j) {
        k = (i + j) / 2;

        if (hash > point[k].hash) {
            i = k + 1;

        } else if (hash < point[k].hash) {
            j = k;

        } else {
            return k;
        }
    }

    return i;
}


static ngx_int_t
ngx_stream_upstream_init_chash_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    uint32_t                               hash;
    ngx_stream_upstream_hash_srv_conf_t   *hcf;
    ngx_stream_upstream_hash_peer_data_t  *hp;

    if (ngx_stream_upstream_init_hash_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_stream_upstream_get_chash_peer;

    hp = s->upstream->peer.data;
    hcf = ngx_stream_conf_upstream_srv_conf(us,
                                            ngx_stream_upstream_hash_module);

    hash = ngx_crc32_long(hp->key.data, hp->key.len);

    ngx_stream_upstream_rr_peers_rlock(hp->rrp.peers);

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (hp->rrp.peers->config
        && (hcf->points == NULL || hcf->config != *hp->rrp.peers->config))
    {
        if (ngx_stream_upstream_update_chash(NULL, us) != NGX_OK) {
            ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
            return NGX_ERROR;
        }

        hcf->config = *hp->rrp.peers->config;
    }
#endif

    if (hcf->points->number) {
        hp->hash = ngx_stream_upstream_find_chash_point(hcf->points, hash);
    }

    ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_hash_peer_data_t *hp = data;

    time_t                                now;
    intptr_t                              m;
    ngx_str_t                            *server;
    ngx_int_t                             total;
    ngx_uint_t                            i, n, best_i;
    ngx_stream_upstream_rr_peer_t        *peer, *best;
    ngx_stream_upstream_chash_point_t    *point;
    ngx_stream_upstream_chash_points_t   *points;
    ngx_stream_upstream_hash_srv_conf_t  *hcf;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get consistent hash peer, try: %ui", pc->tries);

    ngx_stream_upstream_rr_peers_wlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    pc->connection = NULL;

    if (hp->rrp.peers->number == 0) {
        pc->name = hp->rrp.peers->name;
        ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return NGX_BUSY;
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (hp->rrp.peers->config && hp->rrp.config != *hp->rrp.peers->config) {
        pc->name = hp->rrp.peers->name;
        ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return NGX_BUSY;
    }
#endif

    now = ngx_time();
    hcf = hp->conf;

    points = hcf->points;
    point = &points->point[0];

    for ( ;; ) {
        server = point[hp->hash % points->number].server;

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "consistent hash peer:%uD, server:\"%V\"",
                       hp->hash, server);

        best = NULL;
        best_i = 0;
        total = 0;

        for (peer = hp->rrp.peers->peer, i = 0;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (hp->rrp.tried[n] & m) {
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

            if (peer->server.len != server->len
                || ngx_strncmp(peer->server.data, server->data, server->len)
                   != 0)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (best == NULL || peer->current_weight > best->current_weight) {
                best = peer;
                best_i = i;
            }
        }

        if (best) {
            best->current_weight -= total;
            break;
        }

        hp->hash++;
        hp->tries++;

        if (hp->tries > 20) {
            ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

    hp->rrp.current = best;
    ngx_stream_upstream_rr_peer_ref(hp->rrp.peers, best);

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    hp->rrp.tried[n] |= m;

    return NGX_OK;
}


static void *
ngx_stream_upstream_hash_create_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_hash_srv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_stream_upstream_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->points = NULL;

    return conf;
}


static char *
ngx_stream_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_hash_srv_conf_t  *hcf = conf;

    ngx_str_t                           *value;
    ngx_stream_upstream_srv_conf_t      *uscf;
    ngx_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &hcf->key;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->flags = NGX_STREAM_UPSTREAM_CREATE
                  |NGX_STREAM_UPSTREAM_MODIFY
                  |NGX_STREAM_UPSTREAM_WEIGHT
                  |NGX_STREAM_UPSTREAM_MAX_CONNS
                  |NGX_STREAM_UPSTREAM_MAX_FAILS
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NGX_STREAM_UPSTREAM_DOWN;

    if (cf->args->nelts == 2) {
        uscf->peer.init_upstream = ngx_stream_upstream_init_hash;

    } else if (ngx_strcmp(value[2].data, "consistent") == 0) {
        uscf->peer.init_upstream = ngx_stream_upstream_init_chash;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
