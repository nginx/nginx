
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_H_INCLUDED_
#define _NGX_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_STREAM_SSL)
#include <ngx_stream_ssl_module.h>
#endif


typedef struct ngx_stream_session_s  ngx_stream_session_t;


#include <ngx_stream_variables.h>
#include <ngx_stream_script.h>
#include <ngx_stream_upstream.h>
#include <ngx_stream_upstream_round_robin.h>


#define NGX_STREAM_OK                        200
#define NGX_STREAM_BAD_REQUEST               400
#define NGX_STREAM_FORBIDDEN                 403
#define NGX_STREAM_INTERNAL_SERVER_ERROR     500
#define NGX_STREAM_BAD_GATEWAY               502
#define NGX_STREAM_SERVICE_UNAVAILABLE       503


typedef struct {
    void                         **main_conf;
    void                         **srv_conf;
} ngx_stream_conf_ctx_t;


typedef struct {
    struct sockaddr               *sockaddr;
    socklen_t                      socklen;
    ngx_str_t                      addr_text;

    unsigned                       set:1;
    unsigned                       default_server:1;
    unsigned                       bind:1;
    unsigned                       wildcard:1;
    unsigned                       ssl:1;
#if (NGX_HAVE_INET6)
    unsigned                       ipv6only:1;
#endif
    unsigned                       deferred_accept:1;
    unsigned                       reuseport:1;
    unsigned                       so_keepalive:2;
    unsigned                       proxy_protocol:1;

    int                            backlog;
    int                            rcvbuf;
    int                            sndbuf;
    int                            type;
#if (NGX_HAVE_SETFIB)
    int                            setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    int                            fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                            tcp_keepidle;
    int                            tcp_keepintvl;
    int                            tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                          *accept_filter;
#endif
} ngx_stream_listen_opt_t;


typedef enum {
    NGX_STREAM_POST_ACCEPT_PHASE = 0,
    NGX_STREAM_PREACCESS_PHASE,
    NGX_STREAM_ACCESS_PHASE,
    NGX_STREAM_SSL_PHASE,
    NGX_STREAM_PREREAD_PHASE,
    NGX_STREAM_CONTENT_PHASE,
    NGX_STREAM_LOG_PHASE
} ngx_stream_phases;


typedef struct ngx_stream_phase_handler_s  ngx_stream_phase_handler_t;

typedef ngx_int_t (*ngx_stream_phase_handler_pt)(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);
typedef ngx_int_t (*ngx_stream_handler_pt)(ngx_stream_session_t *s);
typedef void (*ngx_stream_content_handler_pt)(ngx_stream_session_t *s);


struct ngx_stream_phase_handler_s {
    ngx_stream_phase_handler_pt    checker;
    ngx_stream_handler_pt          handler;
    ngx_uint_t                     next;
};


typedef struct {
    ngx_stream_phase_handler_t    *handlers;
} ngx_stream_phase_engine_t;


typedef struct {
    ngx_array_t                    handlers;
} ngx_stream_phase_t;


typedef struct {
    ngx_array_t                    servers;     /* ngx_stream_core_srv_conf_t */

    ngx_stream_phase_engine_t      phase_engine;

    ngx_hash_t                     variables_hash;

    ngx_array_t                    variables;        /* ngx_stream_variable_t */
    ngx_array_t                    prefix_variables; /* ngx_stream_variable_t */
    ngx_uint_t                     ncaptures;

    ngx_uint_t                     server_names_hash_max_size;
    ngx_uint_t                     server_names_hash_bucket_size;

    ngx_uint_t                     variables_hash_max_size;
    ngx_uint_t                     variables_hash_bucket_size;

    ngx_hash_keys_arrays_t        *variables_keys;

    ngx_array_t                   *ports;

    ngx_stream_phase_t             phases[NGX_STREAM_LOG_PHASE + 1];
} ngx_stream_core_main_conf_t;


typedef struct {
    /* array of the ngx_stream_server_name_t, "server_name" directive */
    ngx_array_t                    server_names;

    ngx_stream_content_handler_pt  handler;

    ngx_stream_conf_ctx_t         *ctx;

    u_char                        *file_name;
    ngx_uint_t                     line;

    ngx_str_t                      server_name;

    ngx_flag_t                     tcp_nodelay;
    size_t                         preread_buffer_size;
    ngx_msec_t                     preread_timeout;

    ngx_log_t                     *error_log;

    ngx_msec_t                     resolver_timeout;
    ngx_resolver_t                *resolver;

    ngx_msec_t                     proxy_protocol_timeout;

    unsigned                       listen:1;
#if (NGX_PCRE)
    unsigned                       captures:1;
#endif
} ngx_stream_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (NGX_PCRE)
    ngx_stream_regex_t            *regex;
#endif
    ngx_stream_core_srv_conf_t    *server;   /* virtual name server conf */
    ngx_str_t                      name;
} ngx_stream_server_name_t;


typedef struct {
    ngx_hash_combined_t            names;

    ngx_uint_t                     nregex;
    ngx_stream_server_name_t      *regex;
} ngx_stream_virtual_names_t;


typedef struct {
    /* the default server configuration for this address:port */
    ngx_stream_core_srv_conf_t    *default_server;

    ngx_stream_virtual_names_t    *virtual_names;

    unsigned                       ssl:1;
    unsigned                       proxy_protocol:1;
} ngx_stream_addr_conf_t;


typedef struct {
    in_addr_t                      addr;
    ngx_stream_addr_conf_t         conf;
} ngx_stream_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr                addr6;
    ngx_stream_addr_conf_t         conf;
} ngx_stream_in6_addr_t;

#endif


typedef struct {
    /* ngx_stream_in_addr_t or ngx_stream_in6_addr_t */
    void                          *addrs;
    ngx_uint_t                     naddrs;
} ngx_stream_port_t;


typedef struct {
    int                            family;
    int                            type;
    in_port_t                      port;
    ngx_array_t                    addrs; /* array of ngx_stream_conf_addr_t */
} ngx_stream_conf_port_t;


typedef struct {
    ngx_stream_listen_opt_t        opt;

    unsigned                       protocols:3;
    unsigned                       protocols_set:1;
    unsigned                       protocols_changed:1;

    ngx_hash_t                     hash;
    ngx_hash_wildcard_t           *wc_head;
    ngx_hash_wildcard_t           *wc_tail;

#if (NGX_PCRE)
    ngx_uint_t                     nregex;
    ngx_stream_server_name_t      *regex;
#endif

    /* the default server configuration for this address:port */
    ngx_stream_core_srv_conf_t    *default_server;
    ngx_array_t                    servers;
                                      /* array of ngx_stream_core_srv_conf_t */
} ngx_stream_conf_addr_t;


struct ngx_stream_session_s {
    uint32_t                       signature;         /* "STRM" */

    ngx_connection_t              *connection;

    off_t                          received;
    time_t                         start_sec;
    ngx_msec_t                     start_msec;

    ngx_log_handler_pt             log_handler;

    void                         **ctx;
    void                         **main_conf;
    void                         **srv_conf;

    ngx_stream_virtual_names_t    *virtual_names;

    ngx_stream_upstream_t         *upstream;
    ngx_array_t                   *upstream_states;
                                           /* of ngx_stream_upstream_state_t */
    ngx_stream_variable_value_t   *variables;

#if (NGX_PCRE)
    ngx_uint_t                     ncaptures;
    int                           *captures;
    u_char                        *captures_data;
#endif

    ngx_int_t                      phase_handler;
    ngx_uint_t                     status;

    unsigned                       ssl:1;

    unsigned                       stat_processing:1;

    unsigned                       health_check:1;

    unsigned                       limit_conn_status:2;
};


typedef struct {
    ngx_int_t                    (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t                    (*postconfiguration)(ngx_conf_t *cf);

    void                        *(*create_main_conf)(ngx_conf_t *cf);
    char                        *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(ngx_conf_t *cf);
    char                        *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                                   void *conf);
} ngx_stream_module_t;


#define NGX_STREAM_MODULE       0x4d525453     /* "STRM" */

#define NGX_STREAM_MAIN_CONF    0x02000000
#define NGX_STREAM_SRV_CONF     0x04000000
#define NGX_STREAM_UPS_CONF     0x08000000


#define NGX_STREAM_MAIN_CONF_OFFSET  offsetof(ngx_stream_conf_ctx_t, main_conf)
#define NGX_STREAM_SRV_CONF_OFFSET   offsetof(ngx_stream_conf_ctx_t, srv_conf)


#define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define ngx_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define ngx_stream_conf_get_module_main_conf(cf, module)                       \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_stream_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_stream_module.index] ?                                \
        ((ngx_stream_conf_ctx_t *) cycle->conf_ctx[ngx_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


#define NGX_STREAM_WRITE_BUFFERED  0x10


ngx_int_t ngx_stream_add_listen(ngx_conf_t *cf,
    ngx_stream_core_srv_conf_t *cscf, ngx_stream_listen_opt_t *lsopt);

void ngx_stream_core_run_phases(ngx_stream_session_t *s);
ngx_int_t ngx_stream_core_generic_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);
ngx_int_t ngx_stream_core_preread_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);
ngx_int_t ngx_stream_core_content_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);

ngx_int_t ngx_stream_validate_host(ngx_str_t *host, ngx_pool_t *pool,
    ngx_uint_t alloc);
ngx_int_t ngx_stream_find_virtual_server(ngx_stream_session_t *s,
    ngx_str_t *host, ngx_stream_core_srv_conf_t **cscfp);

void ngx_stream_init_connection(ngx_connection_t *c);
void ngx_stream_session_handler(ngx_event_t *rev);
void ngx_stream_finalize_session(ngx_stream_session_t *s, ngx_uint_t rc);


extern ngx_module_t  ngx_stream_module;
extern ngx_uint_t    ngx_stream_max_module;
extern ngx_module_t  ngx_stream_core_module;


typedef ngx_int_t (*ngx_stream_filter_pt)(ngx_stream_session_t *s,
    ngx_chain_t *chain, ngx_uint_t from_upstream);


extern ngx_stream_filter_pt  ngx_stream_top_filter;


#endif /* _NGX_STREAM_H_INCLUDED_ */
