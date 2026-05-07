/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_round_robin.h>


#define NGX_HTTP_TUNNEL_FT_DENIED  0x20000000


typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream;
    ngx_http_complex_value_t        *upstream_value;
    ngx_http_upstream_local_t       *local;
    ngx_array_t                     *allow_upstream;

    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       next_upstream_timeout;

    size_t                           buffer_size;
    size_t                           send_lowat;

    ngx_uint_t                       next_upstream;
    ngx_uint_t                       next_upstream_tries;

    ngx_flag_t                       bind_dynamic;
    ngx_flag_t                       socket_keepalive;
} ngx_http_tunnel_loc_conf_t;


typedef struct {
    ngx_http_upstream_state_t       *state;
    ngx_uint_t                       header_sent:1;
    ngx_uint_t                       connected:1;
    ngx_uint_t                       protocol_tunnel:1;
    ngx_uint_t                       request_body_done:1;
    ngx_uint_t                       upstream_write_shutdown:1;
    ngx_uint_t                       local_set:1;
    ngx_uint_t                       held:1;
    ngx_uint_t                       finalized:1;
} ngx_http_tunnel_ctx_t;


static ngx_int_t ngx_http_tunnel_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_eval(ngx_http_request_t *r,
    ngx_http_tunnel_loc_conf_t *tlcf);
static ngx_int_t ngx_http_tunnel_allow(ngx_http_request_t *r,
    ngx_http_tunnel_loc_conf_t *tlcf);
static ngx_int_t ngx_http_tunnel_set_local(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_http_upstream_local_t *local);
static void ngx_http_tunnel_body_handler(ngx_http_request_t *r);
static void ngx_http_tunnel_connect(ngx_http_request_t *r);
static void ngx_http_tunnel_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_http_tunnel_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_tunnel_test_connect(ngx_connection_t *c);
static void ngx_http_tunnel_init_upstream(ngx_http_request_t *r);
static void ngx_http_tunnel_send_response_handler(ngx_http_request_t *r);
static void ngx_http_tunnel_start(ngx_http_request_t *r);
static void ngx_http_tunnel_start_protocol(ngx_http_request_t *r);
static void ngx_http_tunnel_upstream_handler(ngx_event_t *ev);
static void ngx_http_tunnel_downstream_handler(ngx_http_request_t *r);
static void ngx_http_tunnel_process(ngx_http_request_t *r,
    ngx_uint_t from_upstream, ngx_uint_t do_write);
static void ngx_http_tunnel_process_protocol(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_send_request_body(ngx_http_request_t *r,
    ngx_uint_t do_write);
static ngx_uint_t ngx_http_tunnel_status(ngx_uint_t ft_type);
static void ngx_http_tunnel_next_upstream(ngx_http_request_t *r,
    ngx_uint_t ft_type);
static void ngx_http_tunnel_finalize(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_tunnel_cleanup(void *data);
static void *ngx_http_tunnel_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_tunnel_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_tunnel_allow_upstream(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_conf_bitmask_t  ngx_http_tunnel_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("denied"), NGX_HTTP_TUNNEL_FT_DENIED },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_tunnel_commands[] = {

    { ngx_string("tunnel_pass"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
          |NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_tunnel_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tunnel_allow_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_tunnel_allow_upstream,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tunnel_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, local),
      NULL },

    { ngx_string("tunnel_bind_dynamic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, bind_dynamic),
      NULL },

    { ngx_string("tunnel_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, buffer_size),
      NULL },

    { ngx_string("tunnel_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, connect_timeout),
      NULL },

    { ngx_string("tunnel_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, read_timeout),
      NULL },

    { ngx_string("tunnel_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, send_timeout),
      NULL },

    { ngx_string("tunnel_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, send_lowat),
      NULL },

    { ngx_string("tunnel_socket_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, socket_keepalive),
      NULL },

    { ngx_string("tunnel_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, next_upstream),
      &ngx_http_tunnel_next_upstream_masks },

    { ngx_string("tunnel_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, next_upstream_timeout),
      NULL },

    { ngx_string("tunnel_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, next_upstream_tries),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_tunnel_module_ctx = {
    NULL,                                 /* preconfiguration */
    NULL,                                 /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_tunnel_create_loc_conf,      /* create location configuration */
    ngx_http_tunnel_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_tunnel_module = {
    NGX_MODULE_V1,
    &ngx_http_tunnel_module_ctx,          /* module context */
    ngx_http_tunnel_commands,             /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_tunnel_handler(ngx_http_request_t *r)
{
    ngx_http_cleanup_t         *cln;
    ngx_http_upstream_t        *u;
    ngx_http_tunnel_ctx_t      *ctx;
    ngx_http_tunnel_loc_conf_t *tlcf;
    ngx_int_t                   rc;

    if (r->method != NGX_HTTP_CONNECT) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r != r->main) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_tunnel_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_tunnel_module);

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);
    u = r->upstream;

    u->output.tag = (ngx_buf_tag_t) &ngx_http_tunnel_module;

#if (NGX_HTTP_V2)
    if (r->stream) {
        ctx->protocol_tunnel = 1;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30) {
        ctx->protocol_tunnel = 1;
    }
#endif

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_tunnel_cleanup;
    cln->data = r;

    rc = ngx_http_tunnel_eval(r, tlcf);
    if (rc == NGX_AGAIN) {
        r->count++;
        ctx->held = 1;
        return NGX_DONE;
    }

    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_GATEWAY;
    }

    r->count++;
    ctx->held = 1;

    if (ctx->protocol_tunnel) {
        r->request_body_no_buffering = 1;

        rc = ngx_http_read_client_request_body(r, ngx_http_tunnel_body_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ctx->held = 0;
            r->count--;
            return rc;
        }

        return NGX_DONE;
    }

    ngx_http_tunnel_connect(r);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_tunnel_eval(ngx_http_request_t *r, ngx_http_tunnel_loc_conf_t *tlcf)
{
    ngx_str_t                      host;
    ngx_url_t                      url;
    ngx_uint_t                     i;
    ngx_http_upstream_t           *u;
    ngx_http_upstream_srv_conf_t  *uscf, **uscfp;
    ngx_http_upstream_main_conf_t *umcf;

    u = r->upstream;

    if (tlcf->upstream) {
        u->upstream = tlcf->upstream;
        goto found;
    }

    if (tlcf->upstream_value) {
        if (ngx_http_complex_value(r, tlcf->upstream_value, &host) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memzero(&url, sizeof(ngx_url_t));

        url.url = host;
        url.no_resolve = 1;

        if (ngx_parse_url(r->pool, &url) != NGX_OK) {
            if (url.err) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "%s in upstream \"%V\"", url.err, &url.url);
            }

            return NGX_ERROR;
        }

        u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
        if (u->resolved == NULL) {
            return NGX_ERROR;
        }

        if (url.addrs) {
            u->resolved->sockaddr = url.addrs[0].sockaddr;
            u->resolved->socklen = url.addrs[0].socklen;
            u->resolved->name = url.addrs[0].name;
            u->resolved->naddrs = 1;
        }

        u->resolved->host = url.host;
        u->resolved->port = url.port;
        u->resolved->no_port = url.no_port;
    }

    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    host = u->resolved->host;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->host.len == host.len
            && ((uscf->port == 0 && u->resolved->no_port)
                 || uscf->port == u->resolved->port)
            && ngx_strncasecmp(uscf->host.data, host.data, host.len) == 0)
        {
            u->upstream = uscf;
            goto found;
        }
    }

    if (u->resolved->sockaddr) {
        if (u->resolved->port == 0
            && u->resolved->sockaddr->sa_family != AF_UNIX)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", &host);
            return NGX_ERROR;
        }

        if (ngx_http_upstream_create_round_robin_peer(r, u->resolved)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        u->peer.start_time = ngx_current_msec;
        goto tries;
    }

    if (u->resolved->port == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no port in upstream \"%V\"", &host);
        return NGX_ERROR;
    }

    {
        ngx_resolver_ctx_t        *ctx, temp;
        ngx_http_core_loc_conf_t  *clcf;

        temp.name = host;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", &host);
            return NGX_ERROR;
        }

        ctx->name = host;
        ctx->handler = ngx_http_tunnel_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

found:

    if (u->upstream == NULL) {
        return NGX_ERROR;
    }

    if (u->upstream->peer.init(r, u->upstream) != NGX_OK) {
        return NGX_ERROR;
    }

    u->peer.start_time = ngx_current_msec;

tries:

    if (tlcf->next_upstream_tries && u->peer.tries > tlcf->next_upstream_tries) {
        u->peer.tries = tlcf->next_upstream_tries;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tunnel_allow(ngx_http_request_t *r, ngx_http_tunnel_loc_conf_t *tlcf)
{
    ngx_uint_t                 i;
    ngx_str_t                  value;
    ngx_http_complex_value_t  *cv;

    if (tlcf->allow_upstream == NULL) {
        return NGX_OK;
    }

    cv = tlcf->allow_upstream->elts;

    for (i = 0; i < tlcf->allow_upstream->nelts; i++) {
        if (ngx_http_complex_value(r, &cv[i], &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len == 0
            || (value.len == 1 && value.data[0] == '0'))
        {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tunnel_set_local(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_http_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        u->peer.local = NULL;
        return NGX_OK;
    }

    addr = ngx_palloc(r->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        u->peer.local = NULL;
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}


static void
ngx_http_tunnel_body_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_connect(r);
}


static void
ngx_http_tunnel_connect(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_tunnel_ctx_t      *ctx;
    ngx_http_tunnel_loc_conf_t *tlcf;
    ngx_connection_t           *c, *pc;

    c = r->connection;
    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (u->resolved && u->resolved->ctx) {
        return;
    }

    if (r->upstream_states == NULL) {
        r->upstream_states = ngx_array_create(r->pool, 1,
                                              sizeof(ngx_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (tlcf->bind_dynamic || !ctx->local_set) {
        if (ngx_http_tunnel_set_local(r, u, tlcf->local) != NGX_OK) {
            ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->local_set = 1;
    }

    if (tlcf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    rc = ngx_http_tunnel_allow(r, tlcf);
    if (rc == NGX_DECLINED) {
        ngx_http_tunnel_next_upstream(r, NGX_HTTP_TUNNEL_FT_DENIED);
        return;
    }

    if (rc != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state = ngx_array_push(r->upstream_states);
    if (ctx->state == NULL) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state = ctx->state;

    ngx_memzero(ctx->state, sizeof(ngx_http_upstream_state_t));
    ctx->state->connect_time = (ngx_msec_t) -1;
    ctx->state->header_time = (ngx_msec_t) -1;
    ctx->state->response_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    if (rc == NGX_ERROR) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_http_tunnel_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    pc = u->peer.connection;
    pc->data = r;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc == NGX_AGAIN) {
        pc->read->handler = ngx_http_tunnel_connect_handler;
        pc->write->handler = ngx_http_tunnel_connect_handler;
        ngx_add_timer(pc->write, tlcf->connect_timeout);
        ngx_http_tunnel_connect_handler(pc->write);
        return;
    }

    ngx_http_tunnel_init_upstream(r);
}


static void
ngx_http_tunnel_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_http_request_t            *r;
    ngx_http_upstream_t          *u;
    ngx_http_upstream_resolved_t *ur;

    r = ctx->data;
    u = r->upstream;
    ur = u->resolved;

    ngx_http_set_log_request(r->connection->log, r);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));
        ngx_http_tunnel_finalize(r, NGX_HTTP_BAD_GATEWAY);
        goto done;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

    if (ngx_http_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        goto done;
    }

    u->peer.start_time = ngx_current_msec;

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    ngx_http_tunnel_connect(r);

    return;

done:

    ngx_resolve_name_done(ctx);
    if (ur) {
        ur->ctx = NULL;
    }
}


static void
ngx_http_tunnel_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t            *c;
    ngx_http_request_t          *r;
    ngx_http_tunnel_loc_conf_t *tlcf;
    ngx_int_t                   rc;

    c = ev->data;
    r = c->data;
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (ev->timedout) {
        ngx_http_tunnel_next_upstream(r, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    rc = ngx_http_tunnel_test_connect(c);

    if (rc == NGX_AGAIN) {
        if (!c->write->timer_set) {
            ngx_add_timer(c->write, tlcf->connect_timeout);
        }

        return;
    }

    if (rc != NGX_OK) {
        ngx_http_tunnel_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    ngx_http_tunnel_init_upstream(r);
}


static ngx_int_t
ngx_http_tunnel_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;
            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err,
                                        "kevent() reported connect() failure");
            return NGX_ERROR;
        }
    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
            err = ngx_socket_errno;
        }

        if (err == NGX_EINPROGRESS
#if (NGX_HAVE_EAGAIN)
            || err == NGX_EAGAIN
#endif
#ifdef NGX_EALREADY
            || err == NGX_EALREADY
#endif
           )
        {
            return NGX_AGAIN;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_http_tunnel_init_upstream(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_tunnel_ctx_t      *ctx;
    ngx_http_tunnel_loc_conf_t *tlcf;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_connection_t           *c, *pc;

    c = r->connection;
    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    pc = u->peer.connection;

    if (clcf->tcp_nodelay) {
        if (ngx_tcp_nodelay(c) != NGX_OK || ngx_tcp_nodelay(pc) != NGX_OK) {
            ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = ngx_pnalloc(r->pool, tlcf->buffer_size);
        if (u->buffer.start == NULL) {
            ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + tlcf->buffer_size;
        u->from_client.start = NULL;
    }

    ctx->connected = 1;
    ctx->state->connect_time = ngx_current_msec - u->peer.start_time;

    r->keepalive = 0;
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.status_line, "200 Connection Established");
    r->headers_out.content_length_n = -1;
    ngx_str_null(&r->headers_out.content_type);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
        ngx_http_tunnel_finalize(r, rc);
        return;
    }

    ctx->header_sent = 1;

    if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->buffered || r->postponed || c->buffered) {
        r->read_event_handler = ngx_http_block_reading;
        r->write_event_handler = ngx_http_tunnel_send_response_handler;

        if (!c->write->delayed) {
            ngx_add_timer(c->write, clcf->send_timeout);
        }

        if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
            ngx_http_tunnel_finalize(r, NGX_ERROR);
        }

        return;
    }

    ngx_http_tunnel_start(r);
}


static void
ngx_http_tunnel_send_response_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    wev = c->write;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (wev->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_tunnel_finalize(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_output_filter(r, NULL);
    if (rc == NGX_ERROR) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if (r->buffered || r->postponed || c->buffered) {
        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_tunnel_finalize(r, NGX_ERROR);
        }

        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    ngx_http_tunnel_start(r);
}


static void
ngx_http_tunnel_start(ngx_http_request_t *r)
{
    size_t                size, alloc;
    u_char               *p;
    ngx_http_tunnel_ctx_t  *ctx;
    ngx_http_upstream_t    *u;
    ngx_connection_t       *pc;
    ngx_http_tunnel_loc_conf_t *tlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    u = r->upstream;
    pc = u->peer.connection;
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (ctx->protocol_tunnel) {
        ngx_http_tunnel_start_protocol(r);
        return;
    }

    pc->read->handler = ngx_http_tunnel_upstream_handler;
    pc->write->handler = ngx_http_tunnel_upstream_handler;
    r->read_event_handler = ngx_http_tunnel_downstream_handler;
    r->write_event_handler = ngx_http_tunnel_downstream_handler;

    if (r->header_in->last > r->header_in->pos) {
        size = r->header_in->last - r->header_in->pos;

        if (u->from_client.start == NULL
            || (size_t) (u->from_client.end - u->from_client.start) < size)
        {
            alloc = ngx_max(size, tlcf->buffer_size);

            p = ngx_palloc(r->pool, alloc);
            if (p == NULL) {
                ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            u->from_client.start = p;
            u->from_client.end = p + alloc;
            u->from_client.temporary = 1;
            u->from_client.tag = u->output.tag;
        }

        u->from_client.pos = u->from_client.start;
        u->from_client.last = ngx_cpymem(u->from_client.start,
                                         r->header_in->pos, size);
        r->header_in->pos = r->header_in->last;
    }

    if (u->from_client.pos < u->from_client.last) {
        ngx_http_tunnel_process(r, 0, pc->write->ready);
        return;
    }

    if (pc->read->ready || u->buffer.pos < u->buffer.last) {
        ngx_http_tunnel_process(r, 1, r->connection->write->ready);
        return;
    }

    ngx_http_tunnel_process(r, 0, pc->write->ready);
}


static void
ngx_http_tunnel_start_protocol(ngx_http_request_t *r)
{
    ngx_http_upstream_t       *u;
    ngx_connection_t          *pc;
    ngx_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    pc = u->peer.connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->length = -1;
    u->buffer.tag = u->output.tag;
    u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
    u->input_filter = ngx_http_upstream_non_buffered_filter;
    u->input_filter_ctx = r;

    if (u->input_filter_init(u->input_filter_ctx) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = pc;
    u->writer.limit = clcf->sendfile_max_chunk;
    u->writer.pool = r->pool;

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;
    u->output.output_filter = ngx_chain_writer;
    u->output.filter_ctx = &u->writer;
    u->output.sendfile = pc->sendfile;

    pc->read->handler = ngx_http_tunnel_upstream_handler;
    pc->write->handler = ngx_http_tunnel_upstream_handler;
    r->read_event_handler = ngx_http_tunnel_downstream_handler;
    r->write_event_handler = ngx_http_tunnel_downstream_handler;

    ngx_http_tunnel_process_protocol(r);
}


static void
ngx_http_tunnel_upstream_handler(ngx_event_t *ev)
{
    ngx_connection_t   *c;
    ngx_http_request_t *r;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);

    if (ctx->protocol_tunnel) {
        ngx_http_tunnel_process_protocol(r);
        return;
    }

    ngx_http_tunnel_process(r, 1, r->connection->write->ready);

    if (!ctx->finalized) {
        ngx_http_tunnel_process(r, 0, r->upstream->peer.connection->write->ready);
    }
}


static void
ngx_http_tunnel_downstream_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);

    if (ctx->protocol_tunnel) {
        ngx_http_tunnel_process_protocol(r);
        return;
    }

    ngx_http_tunnel_process(r, 0, r->upstream->peer.connection->write->ready);

    if (!ctx->finalized) {
        ngx_http_tunnel_process(r, 1, r->connection->write->ready);
    }
}


static void
ngx_http_tunnel_process(ngx_http_request_t *r, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    ngx_uint_t                 flags;
    ngx_buf_t                 *b;
    ngx_connection_t          *src, *dst, *c, *pc;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_tunnel_loc_conf_t *tlcf;

    c = r->connection;
    u = r->upstream;
    pc = u->peer.connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (c->write->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_tunnel_finalize(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (pc->read->timedout || pc->write->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_tunnel_finalize(r, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->buffer;

    } else {
        src = c;
        dst = pc;
        b = &u->from_client;

        if (b->start == NULL) {
            b->start = ngx_palloc(r->pool, tlcf->buffer_size);
            if (b->start == NULL) {
                ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            b->pos = b->start;
            b->last = b->start;
            b->end = b->start + tlcf->buffer_size;
            b->temporary = 1;
            b->tag = u->output.tag;
        }
    }

    for ( ;; ) {

        if (do_write) {
            size = b->last - b->pos;

            if (size && dst->write->ready) {
                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_http_tunnel_finalize(r, NGX_ERROR);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {
            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                if (from_upstream) {
                    u->state->bytes_received += n;
                    u->state->response_length += n;
                }

                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    if ((pc->read->eof && u->buffer.pos == u->buffer.last)
        || (c->read->eof && u->from_client.pos == u->from_client.last)
        || (c->read->eof && pc->read->eof))
    {
        ngx_http_tunnel_finalize(r, 0);
        return;
    }

    if (ngx_handle_write_event(pc->write, tlcf->send_lowat) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if (pc->write->active && !pc->write->ready) {
        ngx_add_timer(pc->write, tlcf->send_timeout);
    } else if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if (c->write->active && !c->write->ready) {
        ngx_add_timer(c->write, tlcf->read_timeout);
    } else if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    flags = (pc->read->eof || pc->read->error) ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(pc->read, flags) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if (pc->read->active && !pc->read->ready) {
        ngx_add_timer(pc->read, tlcf->read_timeout);
    } else if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if (c->read->active && !c->read->ready) {
        ngx_add_timer(c->read, tlcf->read_timeout);
    } else if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
}


static void
ngx_http_tunnel_process_protocol(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_uint_t                 flags;
    ngx_buf_t                 *b;
    ngx_connection_t          *c, *pc;
    ngx_http_upstream_t       *u;
    ngx_http_tunnel_ctx_t     *ctx;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_tunnel_loc_conf_t *tlcf;

    c = r->connection;
    u = r->upstream;
    pc = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (c->write->timedout || c->read->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_tunnel_finalize(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (pc->read->timedout || pc->write->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_tunnel_finalize(r, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    for ( ;; ) {

        if (u->out_bufs || u->busy_bufs || c->buffered) {
            rc = ngx_http_output_filter(r, u->out_bufs);

            if (rc == NGX_ERROR) {
                ngx_http_tunnel_finalize(r, NGX_ERROR);
                return;
            }

            ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
                                    &u->out_bufs, u->output.tag);
        }

        rc = ngx_http_tunnel_send_request_body(r, pc->write->ready);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_tunnel_finalize(r, rc);
            return;
        }

        if (ctx->request_body_done
            && !ctx->upstream_write_shutdown
            && u->writer.out == NULL
            && !u->request_body_blocked
            && pc->type == SOCK_STREAM)
        {
            if (ngx_shutdown_socket(pc->fd, NGX_WRITE_SHUTDOWN) == -1) {
                ngx_connection_error(pc, ngx_socket_errno,
                                     ngx_shutdown_socket_n " failed");
                ngx_http_tunnel_finalize(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            ctx->upstream_write_shutdown = 1;
        }

        if (u->busy_bufs || c->buffered) {
            break;
        }

        b = &u->buffer;

        if (b->pos == b->last) {
            b->pos = b->start;
            b->last = b->start;
        }

        size = b->end - b->last;

        if (size && pc->read->ready) {
            n = pc->recv(pc, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n > 0) {
                u->state->bytes_received += n;
                u->state->response_length += n;

                if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
                    ngx_http_tunnel_finalize(r, NGX_ERROR);
                    return;
                }

                continue;
            }

            if (n == 0) {
                pc->read->eof = 1;

            } else {
                pc->read->error = 1;
            }
        }

        break;
    }

    if ((pc->read->eof || pc->read->error)
        && u->out_bufs == NULL
        && u->busy_bufs == NULL
        && !c->buffered)
    {
        ngx_http_tunnel_finalize(r, pc->read->error ? NGX_HTTP_BAD_GATEWAY : 0);
        return;
    }

    if (ngx_handle_write_event(pc->write, tlcf->send_lowat) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if ((u->writer.out || u->request_body_blocked)
        && pc->write->active && !pc->write->ready)
    {
        ngx_add_timer(pc->write, tlcf->send_timeout);
    } else if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    flags = (pc->read->eof || pc->read->error) ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(pc->read, flags) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if (!pc->read->eof && !pc->read->error
        && pc->read->active && !pc->read->ready)
    {
        ngx_add_timer(pc->read, tlcf->read_timeout);
    } else if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }

    if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
        ngx_http_tunnel_finalize(r, NGX_ERROR);
        return;
    }

    if ((u->out_bufs || u->busy_bufs || c->buffered)
        && c->write->active && !c->write->ready)
    {
        ngx_add_timer(c->write, clcf->send_timeout);
    } else if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (r->reading_body) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_tunnel_finalize(r, NGX_ERROR);
            return;
        }

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        if (c->read->active && !c->read->ready) {
            ngx_add_timer(c->read, tlcf->read_timeout);
        }

    } else if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
}


static ngx_int_t
ngx_http_tunnel_send_request_body(ngx_http_request_t *r, ngx_uint_t do_write)
{
    ngx_int_t               rc;
    ngx_chain_t            *out, *ln;
    ngx_connection_t       *c;
    ngx_http_upstream_t    *u;
    ngx_http_tunnel_ctx_t  *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);

    if (r->request_body == NULL) {
        ctx->request_body_done = 1;
        return NGX_OK;
    }

    if (!u->request_sent) {
        u->request_sent = 1;
        out = r->request_body->bufs;
        r->request_body->bufs = NULL;

        c = u->peer.connection;
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        out = NULL;
    }

    for ( ;; ) {

        if (do_write) {
            rc = ngx_output_chain(&u->output, out);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            while (out) {
                ln = out;
                out = out->next;
                ngx_free_chain(r->pool, ln);
            }

            if (rc == NGX_AGAIN) {
                u->request_body_blocked = 1;
                break;
            }

            u->request_body_blocked = 0;

            if (rc == NGX_OK && !r->reading_body) {
                ctx->request_body_done = 1;
                break;
            }
        }

        if (r->reading_body) {
            rc = ngx_http_read_unbuffered_request_body(r);

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            if (rc == NGX_OK) {
                ctx->request_body_done = 1;
            }

            out = r->request_body->bufs;
            r->request_body->bufs = NULL;

        } else {
            ctx->request_body_done = 1;
        }

        if (out == NULL) {
            rc = NGX_AGAIN;
            break;
        }

        do_write = 1;
    }

    return rc;
}


static ngx_uint_t
ngx_http_tunnel_status(ngx_uint_t ft_type)
{
    if (ft_type == NGX_HTTP_TUNNEL_FT_DENIED) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
        return NGX_HTTP_GATEWAY_TIME_OUT;
    }

    return NGX_HTTP_BAD_GATEWAY;
}


static void
ngx_http_tunnel_next_upstream(ngx_http_request_t *r, ngx_uint_t ft_type)
{
    ngx_msec_t                   timeout;
    ngx_uint_t                   state, status;
    ngx_connection_t            *pc;
    ngx_http_upstream_t         *u;
    ngx_http_tunnel_ctx_t       *ctx;
    ngx_http_tunnel_loc_conf_t  *tlcf;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);
    pc = u->peer.connection;

    if (ctx == NULL || ctx->header_sent) {
        ngx_http_tunnel_finalize(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    status = ngx_http_tunnel_status(ft_type);

    state = NGX_PEER_FAILED;

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    timeout = tlcf->next_upstream_timeout;

    if (u->peer.tries == 0
        || (tlcf->next_upstream & NGX_HTTP_UPSTREAM_FT_OFF)
        || !(tlcf->next_upstream & ft_type)
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_http_tunnel_finalize(r, status);
        return;
    }

    if (pc) {
        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    ngx_http_tunnel_connect(r);
}


static void
ngx_http_tunnel_finalize(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_upstream_t    *u;
    ngx_http_tunnel_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL || ctx->finalized) {
        return;
    }

    ctx->finalized = 1;
    u = r->upstream;

    if (ctx->held) {
        ctx->held = 0;

        if (ctx->protocol_tunnel) {
            r->count--;
        }
    }

    if (u) {
        if (u->resolved && u->resolved->ctx) {
            ngx_resolve_name_done(u->resolved->ctx);
            u->resolved->ctx = NULL;
        }

        if (u->peer.connection) {
            ngx_close_connection(u->peer.connection);
            u->peer.connection = NULL;
        }

        if (u->peer.sockaddr) {
            u->peer.free(&u->peer, u->peer.data, 0);
            u->peer.sockaddr = NULL;
        }
    }

    if (ctx->header_sent) {
        if (ctx->protocol_tunnel && rc == 0) {
            r->read_event_handler = ngx_http_block_reading;
            rc = ngx_http_send_special(r, NGX_HTTP_LAST);
        } else {
            rc = 0;
        }
    }

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_tunnel_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_http_tunnel_finalize(r, NGX_ERROR);
}


static void *
ngx_http_tunnel_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_tunnel_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tunnel_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->local = NGX_CONF_UNSET_PTR;
    conf->bind_dynamic = NGX_CONF_UNSET;
    conf->socket_keepalive = NGX_CONF_UNSET;

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->send_lowat = NGX_CONF_UNSET_SIZE;

    conf->next_upstream = 0;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_tunnel_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tunnel_loc_conf_t *prev = parent;
    ngx_http_tunnel_loc_conf_t *conf = child;

    ngx_http_core_loc_conf_t  *clcf;

    if (conf->upstream == NULL && conf->upstream_value == NULL) {
        conf->upstream = prev->upstream;
        conf->upstream_value = prev->upstream_value;
    }

    ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);
    ngx_conf_merge_ptr_value(conf->allow_upstream, prev->allow_upstream, NULL);

    ngx_conf_merge_value(conf->bind_dynamic, prev->bind_dynamic, 0);
    ngx_conf_merge_value(conf->socket_keepalive, prev->socket_keepalive, 0);

    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout,
                              60000);
    ngx_conf_merge_msec_value(conf->read_timeout, prev->read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 16 * 1024);
    ngx_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);

    ngx_conf_merge_bitmask_value(conf->next_upstream, prev->next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_UPSTREAM_FT_ERROR
                                  |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (conf->upstream || conf->upstream_value) {
        clcf->handler = ngx_http_tunnel_handler;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_loc_conf_t *tlcf = conf;

    ngx_http_compile_complex_value_t   ccv;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_core_srv_conf_t          *cscf;
    ngx_uint_t                         n;
    ngx_str_t                         *value, source;
    ngx_url_t                          u;

    if (tlcf->upstream || tlcf->upstream_value) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_tunnel_handler;
    cscf->allow_connect = 1;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {
        ngx_str_set(&source, "$host:$request_port");

    } else {
        source = value[1];
    }

    n = ngx_http_script_variables_count(&source);

    if (n) {
        tlcf->upstream_value = ngx_palloc(cf->pool,
                                          sizeof(ngx_http_complex_value_t));
        if (tlcf->upstream_value == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &source;
        ccv.complex_value = tlcf->upstream_value;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = source;
    u.no_resolve = 1;

    tlcf->upstream = ngx_http_upstream_add(cf, &u, 0);
    if (tlcf->upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_tunnel_allow_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_loc_conf_t      *tlcf = conf;

    ngx_uint_t                       i;
    ngx_str_t                       *value;
    ngx_http_complex_value_t        *cv;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

    if (tlcf->allow_upstream == NGX_CONF_UNSET_PTR || tlcf->allow_upstream == NULL) {
        tlcf->allow_upstream = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                                sizeof(ngx_http_complex_value_t));
        if (tlcf->allow_upstream == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        cv = ngx_array_push(tlcf->allow_upstream);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(cv, sizeof(ngx_http_complex_value_t));
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
