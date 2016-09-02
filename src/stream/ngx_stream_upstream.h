
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_UPSTREAM_H_INCLUDED_
#define _NGX_STREAM_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>


#define NGX_STREAM_UPSTREAM_CREATE        0x0001
#define NGX_STREAM_UPSTREAM_WEIGHT        0x0002
#define NGX_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define NGX_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_STREAM_UPSTREAM_DOWN          0x0010
#define NGX_STREAM_UPSTREAM_BACKUP        0x0020


typedef struct {
    ngx_array_t                        upstreams;
                                           /* ngx_stream_upstream_srv_conf_t */
} ngx_stream_upstream_main_conf_t;


typedef struct ngx_stream_upstream_srv_conf_s  ngx_stream_upstream_srv_conf_t;


typedef ngx_int_t (*ngx_stream_upstream_init_pt)(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_stream_upstream_init_peer_pt)(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);


typedef struct {
    ngx_stream_upstream_init_pt        init_upstream;
    ngx_stream_upstream_init_peer_pt   init;
    void                              *data;
} ngx_stream_upstream_peer_t;


typedef struct {
    ngx_str_t                          name;
    ngx_addr_t                        *addrs;
    ngx_uint_t                         naddrs;
    ngx_uint_t                         weight;
    ngx_uint_t                         max_fails;
    time_t                             fail_timeout;

    unsigned                           down:1;
    unsigned                           backup:1;
} ngx_stream_upstream_server_t;


struct ngx_stream_upstream_srv_conf_s {
    ngx_stream_upstream_peer_t         peer;
    void                             **srv_conf;

    ngx_array_t                       *servers;
                                              /* ngx_stream_upstream_server_t */

    ngx_uint_t                         flags;
    ngx_str_t                          host;
    u_char                            *file_name;
    ngx_uint_t                         line;
    in_port_t                          port;
    ngx_uint_t                         no_port;  /* unsigned no_port:1 */

#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_shm_zone_t                    *shm_zone;
#endif
};


typedef struct {
    ngx_str_t                         *peer;
} ngx_stream_upstream_state_t;


typedef struct {
    ngx_str_t                          host;
    in_port_t                          port;
    ngx_uint_t                         no_port; /* unsigned no_port:1 */

    ngx_uint_t                         naddrs;
    ngx_resolver_addr_t               *addrs;

    struct sockaddr                   *sockaddr;
    socklen_t                          socklen;

    ngx_resolver_ctx_t                *ctx;
} ngx_stream_upstream_resolved_t;


typedef struct {
    ngx_peer_connection_t              peer;
    ngx_buf_t                          downstream_buf;
    ngx_buf_t                          upstream_buf;
    off_t                              received;
    time_t                             start_sec;
    ngx_uint_t                         responses;
#if (NGX_STREAM_SSL)
    ngx_str_t                          ssl_name;
#endif
    ngx_stream_upstream_resolved_t    *resolved;
    ngx_stream_upstream_state_t       *state;
    unsigned                           connected:1;
    unsigned                           proxy_protocol:1;
} ngx_stream_upstream_t;


ngx_stream_upstream_srv_conf_t *ngx_stream_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);


#define ngx_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t  ngx_stream_upstream_module;


#endif /* _NGX_STREAM_UPSTREAM_H_INCLUDED_ */
