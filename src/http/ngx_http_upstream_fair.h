/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011 Zimbra Software, LLC.
 *
 * The contents of this file are subject to the Zimbra Public License
 * Version 1.4 ("License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 * http://www.zimbra.com/license.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied.
 * ***** END LICENSE BLOCK *****
 */

#ifndef _NGX_HTTP_UPSTREAM_FAIR_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_FAIR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_uint_t                          nreq;
    ngx_uint_t                          total_req;
    ngx_uint_t                          last_req_id;
    ngx_uint_t                          fails;
    ngx_uint_t                          current_weight;
} ngx_http_upstream_fair_shared_t;

typedef struct ngx_http_upstream_fair_peers_s ngx_http_upstream_fair_peers_t;

typedef struct {
    ngx_rbtree_node_t                   node;
    ngx_uint_t                          generation;
    uintptr_t                           peers;      /* forms a unique cookie together with generation */
    ngx_uint_t                          total_nreq;
    ngx_uint_t                          total_requests;
    ngx_atomic_t                        lock;
    ngx_http_upstream_fair_shared_t     stats[1];
} ngx_http_upstream_fair_shm_block_t;

/* ngx_spinlock is defined without a matching unlock primitive */
#define ngx_spinlock_unlock(lock)       (void) ngx_atomic_cmp_set(lock, ngx_pid, 0)

typedef struct {
    ngx_http_upstream_fair_shared_t    *shared;
    struct sockaddr                    *sockaddr;
    socklen_t                           socklen;
    ngx_str_t                           name;

    ngx_uint_t                          weight;
    ngx_uint_t                          max_fails;
    time_t                              fail_timeout;

    time_t                              accessed;
    ngx_uint_t                          down:1;
    ngx_str_t                           version;       /* upstream server version */

#if (NGX_HTTP_SSL)
    ngx_ssl_session_t                  *ssl_session;    /* local to a process */
#endif

} ngx_http_upstream_fair_peer_t;

#define NGX_HTTP_UPSTREAM_FAIR_NO_RR            (1<<26)
#define NGX_HTTP_UPSTREAM_FAIR_WEIGHT_MODE_IDLE (1<<27)
#define NGX_HTTP_UPSTREAM_FAIR_WEIGHT_MODE_PEAK (1<<28)
#define NGX_HTTP_UPSTREAM_FAIR_WEIGHT_MODE_MASK ((1<<27) | (1<<28))

enum { WM_DEFAULT = 0, WM_IDLE, WM_PEAK };

struct ngx_http_upstream_fair_peers_s {
    ngx_http_upstream_fair_shm_block_t *shared;
    ngx_uint_t                          current;
    ngx_uint_t                          size_err:1;
    ngx_uint_t                          no_rr:1;
    ngx_uint_t                          weight_mode:2;
    ngx_uint_t                          number;
    ngx_str_t                          *name;
    ngx_http_upstream_fair_peers_t     *next;           /* for backup peers support, not really used yet */
    ngx_http_upstream_fair_peer_t       peer[1];
};


#define NGX_PEER_INVALID (~0UL)

typedef struct {
    ngx_http_upstream_fair_peers_t     *peers;
    ngx_uint_t                          current;
    uintptr_t                          *tried;
    uintptr_t                          *done;
    uintptr_t                           data;
    uintptr_t                           data2;
    ngx_str_t                           version;
    ngx_flag_t                          exact_version_check;
} ngx_http_upstream_fair_peer_data_t;

extern ngx_uint_t *shm_size;

ngx_int_t ngx_http_upstream_init_fair(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_fair_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_get_fair_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_fair_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
ngx_flag_t ngx_http_upstream_fair_peer_version_allowed(ngx_http_upstream_fair_peer_t *peer,
    void* data, ngx_log_t* log);

#endif /* _NGX_HTTP_UPSTREAM_FAIR_H_INCLUDED_ */
