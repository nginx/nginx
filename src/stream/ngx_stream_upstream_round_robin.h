
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct ngx_stream_upstream_rr_peers_s  ngx_stream_upstream_rr_peers_t;
typedef struct ngx_stream_upstream_rr_peer_s   ngx_stream_upstream_rr_peer_t;


#if (NGX_STREAM_UPSTREAM_ZONE)

typedef struct {
    ngx_event_t                      event;         /* must be first */
    ngx_uint_t                       worker;
    ngx_str_t                        name;
    ngx_str_t                        service;
    time_t                           valid;
    ngx_stream_upstream_rr_peers_t  *peers;
    ngx_stream_upstream_rr_peer_t   *peer;
} ngx_stream_upstream_host_t;

#endif


struct ngx_stream_upstream_rr_peer_s {
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;
    ngx_str_t                        server;

    ngx_int_t                        current_weight;
    ngx_int_t                        effective_weight;
    ngx_int_t                        weight;

    ngx_uint_t                       conns;
    ngx_uint_t                       max_conns;

    ngx_uint_t                       fails;
    time_t                           accessed;
    time_t                           checked;

    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    ngx_msec_t                       start_time;

    ngx_uint_t                       down;

    void                            *ssl_session;
    int                              ssl_session_len;

#if (NGX_STREAM_UPSTREAM_ZONE)
    unsigned                         zombie:1;

    ngx_atomic_t                     lock;
    ngx_uint_t                       refs;
    ngx_stream_upstream_host_t      *host;
#endif

    ngx_stream_upstream_rr_peer_t   *next;

    NGX_COMPAT_BEGIN(14)
    NGX_COMPAT_END
};


struct ngx_stream_upstream_rr_peers_s {
    ngx_uint_t                       number;

#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_slab_pool_t                 *shpool;
    ngx_atomic_t                     rwlock;
    ngx_uint_t                      *config;
    ngx_stream_upstream_rr_peer_t   *resolve;
    ngx_stream_upstream_rr_peers_t  *zone_next;
#endif

    ngx_uint_t                       total_weight;
    ngx_uint_t                       tries;

    unsigned                         single:1;
    unsigned                         weighted:1;

    ngx_str_t                       *name;

    ngx_stream_upstream_rr_peers_t  *next;

    ngx_stream_upstream_rr_peer_t   *peer;
};


#if (NGX_STREAM_UPSTREAM_ZONE)

#define ngx_stream_upstream_rr_peers_rlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_stream_upstream_rr_peers_wlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_stream_upstream_rr_peers_unlock(peers)                            \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_stream_upstream_rr_peer_lock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_stream_upstream_rr_peer_unlock(peers, peer)                       \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }


#define ngx_stream_upstream_rr_peer_ref(peers, peer)                          \
    (peer)->refs++;


static ngx_inline void
ngx_stream_upstream_rr_peer_free_locked(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *peer)
{
    if (peer->refs) {
        peer->zombie = 1;
        return;
    }

    ngx_slab_free_locked(peers->shpool, peer->sockaddr);
    ngx_slab_free_locked(peers->shpool, peer->name.data);

    if (peer->server.data) {
        ngx_slab_free_locked(peers->shpool, peer->server.data);
    }

#if (NGX_STREAM_SSL)
    if (peer->ssl_session) {
        ngx_slab_free_locked(peers->shpool, peer->ssl_session);
    }
#endif

    ngx_slab_free_locked(peers->shpool, peer);
}


static ngx_inline void
ngx_stream_upstream_rr_peer_free(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *peer)
{
    ngx_shmtx_lock(&peers->shpool->mutex);
    ngx_stream_upstream_rr_peer_free_locked(peers, peer);
    ngx_shmtx_unlock(&peers->shpool->mutex);
}


static ngx_inline ngx_int_t
ngx_stream_upstream_rr_peer_unref(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *peer)
{
    peer->refs--;

    if (peers->shpool == NULL) {
        return NGX_OK;
    }

    if (peer->refs == 0 && peer->zombie) {
        ngx_stream_upstream_rr_peer_free(peers, peer);
        return NGX_DONE;
    }

    return NGX_OK;
}

#else

#define ngx_stream_upstream_rr_peers_rlock(peers)
#define ngx_stream_upstream_rr_peers_wlock(peers)
#define ngx_stream_upstream_rr_peers_unlock(peers)
#define ngx_stream_upstream_rr_peer_lock(peers, peer)
#define ngx_stream_upstream_rr_peer_unlock(peers, peer)
#define ngx_stream_upstream_rr_peer_ref(peers, peer)
#define ngx_stream_upstream_rr_peer_unref(peers, peer)  NGX_OK

#endif


typedef struct {
    ngx_uint_t                       config;
    ngx_stream_upstream_rr_peers_t  *peers;
    ngx_stream_upstream_rr_peer_t   *current;
    uintptr_t                       *tried;
    uintptr_t                        data;
} ngx_stream_upstream_rr_peer_data_t;


ngx_int_t ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
ngx_int_t ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
ngx_int_t ngx_stream_upstream_create_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_resolved_t *ur);
ngx_int_t ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);


#endif /* _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
