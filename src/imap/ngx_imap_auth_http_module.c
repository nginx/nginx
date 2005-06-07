
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_imap.h>


typedef struct {
    ngx_peers_t            *peers;

    ngx_msec_t              timeout;

    ngx_str_t               host_header;
    ngx_str_t               uri;
} ngx_imap_auth_http_conf_t;


typedef struct {
    ngx_buf_t              *request;
    ngx_peer_connection_t   peer;
} ngx_imap_auth_http_ctx_t;


static void ngx_imap_auth_http_write_handler(ngx_event_t *wev);
static void ngx_imap_auth_http_read_handler(ngx_event_t *rev);
static void ngx_imap_auth_http_block_read(ngx_event_t *rev);
static void ngx_imap_auth_http_dummy_handler(ngx_event_t *ev);
static ngx_buf_t *ngx_imap_auth_http_create_request(ngx_imap_session_t *s,
    ngx_imap_auth_http_conf_t *ahcf);

static void *ngx_imap_auth_http_create_conf(ngx_conf_t *cf);
static char *ngx_imap_auth_http_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_imap_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_imap_auth_http_commands[] = {

    { ngx_string("auth_http"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_imap_auth_http,
      NGX_IMAP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_http_timeout"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_auth_http_conf_t, timeout),
      NULL },

      ngx_null_command
};


static ngx_imap_module_t  ngx_imap_auth_http_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_imap_auth_http_create_conf,        /* create server configuration */
    ngx_imap_auth_http_merge_conf          /* merge server configuration */
};


ngx_module_t  ngx_imap_auth_http_module = {
    NGX_MODULE_V1,
    &ngx_imap_auth_http_module_ctx,        /* module context */
    ngx_imap_auth_http_commands,           /* module directives */
    NGX_IMAP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static char *ngx_imap_auth_http_protocol[] = { "pop3", "imap" };


void
ngx_imap_auth_http_init(ngx_imap_session_t *s)
{
    ngx_int_t                   rc;
    ngx_imap_auth_http_ctx_t   *ctx;
    ngx_imap_auth_http_conf_t  *ahcf;

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_imap_auth_http_ctx_t));
    if (ctx == NULL) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    ahcf = ngx_imap_get_module_srv_conf(s, ngx_imap_auth_http_module);

    ctx->request = ngx_imap_auth_http_create_request(s, ahcf);
    if (ctx->request == NULL) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    ngx_imap_set_ctx(s, ctx, ngx_imap_auth_http_module);

    ctx->peer.peers = ahcf->peers;
    ctx->peer.log = s->connection->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_imap_auth_http_block_read;
    ctx->peer.connection->read->handler = ngx_imap_auth_http_read_handler;
    ctx->peer.connection->write->handler = ngx_imap_auth_http_write_handler;

    if (rc == NGX_OK) {
        ngx_imap_auth_http_write_handler(ctx->peer.connection->write);
        return;
    }

    ngx_add_timer(ctx->peer.connection->read, ahcf->timeout);
    ngx_add_timer(ctx->peer.connection->write, ahcf->timeout);
}


static void
ngx_imap_auth_http_write_handler(ngx_event_t *wev)
{
    ssize_t                     n, size;
    ngx_connection_t           *c;
    ngx_imap_session_t         *s;
    ngx_imap_auth_http_ctx_t   *ctx;
    ngx_imap_auth_http_conf_t  *ahcf;

    c = wev->data;
    s = c->data;

    ctx = ngx_imap_get_module_ctx(s, ngx_imap_auth_http_module);

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, wev->log, 0,
                   "imap auth http write handler");

    if (wev->timedout) {  
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "auth http server timed out");
        ngx_imap_close_connection(ctx->peer.connection);
        ngx_imap_close_connection(s->connection);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = ngx_send(c, ctx->request->pos, size);

    if (n == NGX_ERROR) {
        ngx_imap_close_connection(ctx->peer.connection);
        ngx_imap_close_connection(s->connection);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = ngx_imap_auth_http_dummy_handler;

            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        ahcf = ngx_imap_get_module_srv_conf(s, ngx_imap_auth_http_module);
        ngx_add_timer(wev, ahcf->timeout);
    }
}


static void
ngx_imap_auth_http_read_handler(ngx_event_t *rev)
{
    ngx_peers_t                *peers;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
#if 0
    ngx_imap_auth_http_ctx_t  *ctx;
#endif

    c = rev->data;
    s = c->data;

#if 0
    ctx = ngx_imap_get_module_ctx(s, ngx_imap_auth_http_module);
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                   "imap auth http read handler");

    peers = NULL;

    ngx_imap_proxy_init(s, peers);
}


static void
ngx_imap_auth_http_block_read(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_auth_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                   "imap auth http block read");

    if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
        c = rev->data;
        s = c->data;

        ctx = ngx_imap_get_module_ctx(s, ngx_imap_auth_http_module);

        ngx_imap_close_connection(ctx->peer.connection);
        ngx_imap_close_connection(s->connection);
    }
}


static void
ngx_imap_auth_http_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, ev->log, 0,
                   "imap auth http dummy handler");
}


static ngx_buf_t *
ngx_imap_auth_http_create_request(ngx_imap_session_t *s,
    ngx_imap_auth_http_conf_t *ahcf)
{
    size_t      len;
    ngx_buf_t  *b;

    len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: plain" CRLF) - 1
          + sizeof("Auth-User: ") - 1 + s->login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + s->passwd.len + sizeof(CRLF) - 1
          + sizeof("Auth-Protocol: imap" CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(s->connection->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = ngx_cpymem(b->last, "GET ", sizeof("GET ") - 1);
    b->last = ngx_cpymem(b->last, ahcf->uri.data, ahcf->uri.len);
    b->last = ngx_cpymem(b->last, " HTTP/1.0" CRLF,
                         sizeof(" HTTP/1.0" CRLF) - 1);

    b->last = ngx_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
    b->last = ngx_cpymem(b->last, ahcf->host_header.data,
                         ahcf->host_header.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Method: plain" CRLF,
                         sizeof("Auth-Method: plain" CRLF) - 1);

    b->last = ngx_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = ngx_cpymem(b->last, s->login.data, s->login.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = ngx_cpymem(b->last, s->passwd.data, s->passwd.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = ngx_cpymem(b->last, ngx_imap_auth_http_protocol[s->protocol],
                         sizeof("imap") - 1);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = ngx_cpymem(b->last, s->connection->addr_text.data,
                         s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NGX_DEBUG)
    {
    ngx_str_t  l;

    l.len = b->last - b->pos;
    l.data = b->pos;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "imap auth http header:\n\"%V\"", &l);
    }
#endif

    return b;
}


static void *
ngx_imap_auth_http_create_conf(ngx_conf_t *cf)
{           
    ngx_imap_auth_http_conf_t  *ahcf;
            
    ahcf = ngx_pcalloc(cf->pool, sizeof(ngx_imap_auth_http_conf_t));
    if (ahcf == NULL) {
        return NGX_CONF_ERROR;
    }

    ahcf->timeout = NGX_CONF_UNSET_MSEC;

    return ahcf;
}


static char *
ngx_imap_auth_http_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_imap_auth_http_conf_t *prev = parent;
    ngx_imap_auth_http_conf_t *conf = child;

    if (conf->peers == NULL) {
        conf->peers = prev->peers;
        conf->host_header = prev->host_header;
        conf->uri = prev->uri;
    }

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    return NGX_CONF_OK;
}


static char *
ngx_imap_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{   
    ngx_imap_auth_http_conf_t *ahcf = conf;

    ngx_uint_t                   i;
    ngx_str_t                   *value, *url;
    ngx_inet_upstream_t          inet_upstream;
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_unix_domain_upstream_t   unix_upstream;
#endif
    
    value = cf->args->elts;

    url = &value[1];

    if (ngx_strncasecmp(url->data, "unix:", 5) == 0) {

#if (NGX_HAVE_UNIX_DOMAIN)

        ngx_memzero(&unix_upstream, sizeof(ngx_unix_domain_upstream_t));

        unix_upstream.name = *url;
        unix_upstream.url = *url;
        unix_upstream.uri_part = 1;

        ahcf->peers = ngx_unix_upstream_parse(cf, &unix_upstream);
        if (ahcf->peers == NULL) {
            return NGX_CONF_ERROR;
        }

        ahcf->peers->peer[0].uri_separator = ":";

        ahcf->host_header.len = sizeof("localhost") - 1;
        ahcf->host_header.data = (u_char *) "localhost";
        ahcf->uri = unix_upstream.uri;
    
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the unix domain sockets are not supported "
                           "on this platform");
        return NGX_CONF_ERROR;
    
#endif

    } else {
        ngx_memzero(&inet_upstream, sizeof(ngx_inet_upstream_t));

        inet_upstream.name = *url;
        inet_upstream.url = *url;
        inet_upstream.default_port_value = 80;
        inet_upstream.uri_part = 1;

        ahcf->peers = ngx_inet_upstream_parse(cf, &inet_upstream);
        if (ahcf->peers == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < ahcf->peers->number; i++) {
            ahcf->peers->peer[i].uri_separator = ":";
        }

        ahcf->host_header = inet_upstream.host_header;
        ahcf->uri = inet_upstream.uri;
    }

    return NGX_CONF_OK;
}
