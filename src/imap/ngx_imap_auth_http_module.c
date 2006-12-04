
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_imap.h>


typedef struct {
    ngx_peer_addr_t                *peer;

    ngx_msec_t                      timeout;

    ngx_str_t                       host_header;
    ngx_str_t                       uri;
    ngx_str_t                       header;

    ngx_array_t                    *headers;
} ngx_imap_auth_http_conf_t;


typedef struct ngx_imap_auth_http_ctx_s  ngx_imap_auth_http_ctx_t;

typedef void (*ngx_imap_auth_http_handler_pt)(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx);

struct ngx_imap_auth_http_ctx_s {
    ngx_buf_t                      *request;
    ngx_buf_t                      *response;
    ngx_peer_connection_t           peer;

    ngx_imap_auth_http_handler_pt   handler;

    ngx_uint_t                      state;
    ngx_uint_t                      hash;   /* no needed ? */

    u_char                         *header_name_start;
    u_char                         *header_name_end;
    u_char                         *header_start;
    u_char                         *header_end;

    ngx_str_t                       addr;
    ngx_str_t                       port;
    ngx_str_t                       err;
    ngx_str_t                       errmsg;

    time_t                          sleep;

    ngx_pool_t                     *pool;
};


static void ngx_imap_auth_http_write_handler(ngx_event_t *wev);
static void ngx_imap_auth_http_read_handler(ngx_event_t *rev);
static void ngx_imap_auth_http_ignore_status_line(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx);
static void ngx_imap_auth_http_process_headers(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx);
static void ngx_imap_auth_sleep_handler(ngx_event_t *rev);
static ngx_int_t ngx_imap_auth_http_parse_header_line(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx);
static void ngx_imap_auth_http_block_read(ngx_event_t *rev);
static void ngx_imap_auth_http_dummy_handler(ngx_event_t *ev);
static ngx_buf_t *ngx_imap_auth_http_create_request(ngx_imap_session_t *s,
    ngx_pool_t *pool, ngx_imap_auth_http_conf_t *ahcf);
static ngx_int_t ngx_imap_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text,
    ngx_str_t *escaped);

static void *ngx_imap_auth_http_create_conf(ngx_conf_t *cf);
static char *ngx_imap_auth_http_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_imap_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_imap_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


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

    { ngx_string("auth_http_header"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_imap_auth_http_header,
      NGX_IMAP_SRV_CONF_OFFSET,
      0,
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
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char       *ngx_imap_auth_http_protocol[] = { "pop3", "imap" };
static ngx_str_t   ngx_imap_auth_http_method[] = {
    ngx_string("plain"),
    ngx_string("apop"),
    ngx_string("cram-md5")
};


void
ngx_imap_auth_http_init(ngx_imap_session_t *s)
{
    ngx_int_t                   rc;
    ngx_pool_t                 *pool;
    ngx_imap_auth_http_ctx_t   *ctx;
    ngx_imap_auth_http_conf_t  *ahcf;

    s->connection->log->action = "in http auth state";

    pool = ngx_create_pool(2048, s->connection->log);
    if (pool == NULL) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_imap_auth_http_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        ngx_imap_session_internal_server_error(s);
        return;
    }

    ctx->pool = pool;

    ahcf = ngx_imap_get_module_srv_conf(s, ngx_imap_auth_http_module);

    ctx->request = ngx_imap_auth_http_create_request(s, pool, ahcf);
    if (ctx->request == NULL) {
        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);
        return;
    }

    ngx_imap_set_ctx(s, ctx, ngx_imap_auth_http_module);

    ctx->peer.sockaddr = ahcf->peer->sockaddr;
    ctx->peer.socklen = ahcf->peer->socklen;
    ctx->peer.name = &ahcf->peer->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = s->connection->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (ctx->peer.connection) {
            ngx_close_connection(ctx->peer.connection);
        }

        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_imap_auth_http_block_read;
    ctx->peer.connection->read->handler = ngx_imap_auth_http_read_handler;
    ctx->peer.connection->write->handler = ngx_imap_auth_http_write_handler;

    ctx->handler = ngx_imap_auth_http_ignore_status_line;

    ngx_add_timer(ctx->peer.connection->read, ahcf->timeout);
    ngx_add_timer(ctx->peer.connection->write, ahcf->timeout);

    if (rc == NGX_OK) {
        ngx_imap_auth_http_write_handler(ctx->peer.connection->write);
        return;
    }
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
                      "auth http server %V timed out", ctx->peer.name);
        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = ngx_send(c, ctx->request->pos, size);

    if (n == NGX_ERROR) {
        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = ngx_imap_auth_http_dummy_handler;

            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            if (ngx_handle_write_event(wev, 0) == NGX_ERROR) {
                ngx_close_connection(ctx->peer.connection);
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
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
    ssize_t                     n, size;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_auth_http_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                   "imap auth http read handler");

    ctx = ngx_imap_get_module_ctx(s, ngx_imap_auth_http_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, 1024);
        if (ctx->response == NULL) {
            ngx_close_connection(ctx->peer.connection);
            ngx_destroy_pool(ctx->pool);
            ngx_imap_session_internal_server_error(s);
            return;
        }
    }

    size = ctx->response->end - ctx->response->last;

    n = ngx_recv(c, ctx->response->pos, size);

    if (n > 0) {
        ctx->response->last += n;

        ctx->handler(s, ctx);
        return;
    }

    if (n == NGX_AGAIN) {
        return;
    }

    ngx_close_connection(ctx->peer.connection);
    ngx_destroy_pool(ctx->pool);
    ngx_imap_session_internal_server_error(s);
}


static void
ngx_imap_auth_http_ignore_status_line(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx)
{
    u_char  *p, ch;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_skip,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                   "imap auth http process status line");

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch == 'H') {
                state = sw_H;
                break;
            }
            goto next;

        case sw_H:
            if (ch == 'T') {
                state = sw_HT;
                break;
            }
            goto next;

        case sw_HT:
            if (ch == 'T') {
                state = sw_HTT;
                break;
            }
            goto next;

        case sw_HTT:
            if (ch == 'P') {
                state = sw_HTTP;
                break;
            }
            goto next;

        case sw_HTTP:
            if (ch == '/') {
                state = sw_skip;
                break;
            }
            goto next;

        /* any text until end of line */
        case sw_skip:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            if (ch == LF) {
                goto done;
            }

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "auth http server &V sent invalid response",
                          ctx->peer.name);
            ngx_close_connection(ctx->peer.connection);
            ngx_destroy_pool(ctx->pool);
            ngx_imap_session_internal_server_error(s);
            return;
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return;

next:

    p = ctx->response->start - 1;

done:

    ctx->response->pos = p + 1;
    ctx->state = 0;
    ctx->handler = ngx_imap_auth_http_process_headers;
    ctx->handler(s, ctx);
}


static void
ngx_imap_auth_http_process_headers(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx)
{
    u_char              *p;
    time_t               timer;
    size_t               len, size;
    ngx_int_t            rc, port, n;
    ngx_peer_addr_t     *peer;
    struct sockaddr_in  *sin;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                   "imap auth http process headers");

    for ( ;; ) {
        rc = ngx_imap_auth_http_parse_header_line(s, ctx);

        if (rc == NGX_OK) {

#if (NGX_DEBUG)
            {
            ngx_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            ngx_log_debug2(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                           "auth http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && ngx_strncasecmp(ctx->header_name_start, "Auth-Status",
                                   sizeof("Auth-Status") - 1) == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len == 2
                    && ctx->header_start[0] == 'O'
                    && ctx->header_start[1] == 'K')
                {
                    continue;
                }

                if (len == 4
                    && ctx->header_start[0] == 'W'
                    && ctx->header_start[1] == 'A'
                    && ctx->header_start[2] == 'I'
                    && ctx->header_start[3] == 'T')
                {
                    s->auth_wait = 1;
                    continue;
                }

                ctx->errmsg.len = len;
                ctx->errmsg.data = ctx->header_start;

                if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
                    size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;

                } else {
                    size = s->tag.len + sizeof("NO ") - 1 + len
                           + sizeof(CRLF) - 1;
                }

                p = ngx_pcalloc(s->connection->pool, size);
                if (p == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_imap_session_internal_server_error(s);
                    return;
                }

                ctx->err.data = p;

                if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
                    *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R';

                } else {
                    p = ngx_cpymem(p, s->tag.data, s->tag.len);
                    *p++ = 'N'; *p++ = 'O';
                }

                *p++ = ' ';

                p = ngx_cpymem(p, ctx->header_start, len);
                *p++ = CR; *p++ = LF;

                ctx->err.len = p - ctx->err.data;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && ngx_strncasecmp(ctx->header_name_start, "Auth-Server",
                                   sizeof("Auth-Server") - 1) == 0)
            {
                ctx->addr.len = ctx->header_end - ctx->header_start;
                ctx->addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && ngx_strncasecmp(ctx->header_name_start, "Auth-Port",
                                   sizeof("Auth-Port") - 1) == 0)
            {
                ctx->port.len = ctx->header_end - ctx->header_start;
                ctx->port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-User") - 1
                && ngx_strncasecmp(ctx->header_name_start, "Auth-User",
                                   sizeof("Auth-User") - 1) == 0)
            {
                s->login.len = ctx->header_end - ctx->header_start;

                s->login.data = ngx_palloc(s->connection->pool, s->login.len);
                if (s->login.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_imap_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->login.data, ctx->header_start, s->login.len);

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && ngx_strncasecmp(ctx->header_name_start, "Auth-Pass",
                                   sizeof("Auth-Pass") - 1) == 0)
            {
                s->passwd.len = ctx->header_end - ctx->header_start;

                s->passwd.data = ngx_palloc(s->connection->pool, s->passwd.len);
                if (s->passwd.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_imap_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);

                continue;
            }

            if (len == sizeof("Auth-Wait") - 1
                && ngx_strncasecmp(ctx->header_name_start, "Auth-Wait",
                                   sizeof("Auth-Wait") - 1) == 0)
            {
                n = ngx_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != NGX_ERROR) {
                    ctx->sleep = n;
                }

                continue;
            }

            /* ignore other headers */

            continue;
        }

        if (rc == NGX_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                           "auth http header done");

            ngx_close_connection(ctx->peer.connection);

            if (ctx->err.len) {
                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "client login failed: \"%V\"", &ctx->errmsg);

                s->out = ctx->err;
                timer = ctx->sleep;

                ngx_destroy_pool(ctx->pool);

                if (timer == 0) {
                    s->quit = 1;
                    ngx_imap_send(s->connection->write);
                    return;
                }

                ngx_add_timer(s->connection->read, timer * 1000);

                s->connection->read->handler = ngx_imap_auth_sleep_handler;

                return;
            }

            if (s->auth_wait) {
                timer = ctx->sleep;

                ngx_destroy_pool(ctx->pool);

                if (timer == 0) {
                    ngx_imap_auth_http_init(s);
                    return;
                }

                ngx_add_timer(s->connection->read, timer * 1000);

                s->connection->read->handler = ngx_imap_auth_sleep_handler;

                return;
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send server or port",
                              ctx->peer.name);
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            if (s->passwd.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send password",
                              ctx->peer.name);
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            peer = ngx_pcalloc(s->connection->pool, sizeof(ngx_peer_addr_t));
            if (peer == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            sin = ngx_pcalloc(s->connection->pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            sin->sin_family = AF_INET;

            port = ngx_atoi(ctx->port.data, ctx->port.len);
            if (port == NGX_ERROR || port < 1 || port > 65536) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "port:\"%V\"",
                              ctx->peer.name, &ctx->port);
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            sin->sin_port = htons((in_port_t) port);

            ctx->addr.data[ctx->addr.len] = '\0';
            sin->sin_addr.s_addr = inet_addr((char *) ctx->addr.data);
            if (sin->sin_addr.s_addr == INADDR_NONE) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "address:\"%V\"",
                              ctx->peer.name, &ctx->addr);
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            peer->sockaddr = (struct sockaddr *) sin;
            peer->socklen = sizeof(struct sockaddr_in);

            len = ctx->addr.len + 1 + ctx->port.len;

            peer->name.len = len;

            peer->name.data = ngx_palloc(s->connection->pool, len);
            if (peer->name.data == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_imap_session_internal_server_error(s);
                return;
            }

            len = ctx->addr.len;

            ngx_memcpy(peer->name.data, ctx->addr.data, len);

            peer->name.data[len++] = ':';

            ngx_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);

            ngx_destroy_pool(ctx->pool);
            ngx_imap_proxy_init(s, peer);

            return;
        }

        if (rc == NGX_AGAIN ) {
            return;
        }

        /* rc == NGX_ERROR */

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "auth http server %V sent invalid header in response",
                      ctx->peer.name);
        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);

        return;
    }
}


static void
ngx_imap_auth_sleep_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap auth sleep handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {

        rev->timedout = 0;

        if (s->auth_wait) {
            s->auth_wait = 0;
            ngx_imap_auth_http_init(s);
            return;
        }

        if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
            s->imap_state = ngx_pop3_start;
            s->connection->read->handler = ngx_pop3_auth_state;

        } else {
            s->imap_state = ngx_imap_start;
            s->connection->read->handler = ngx_imap_auth_state;
        }

        s->auth_method = NGX_IMAP_AUTH_PLAIN;

        c->log->action = "in auth state";

        ngx_imap_send(s->connection->write);

        if (c->destroyed) {
            return;
        }

        cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);

        ngx_add_timer(rev, cscf->timeout);

        if (rev->ready) {
            s->connection->read->handler(rev);
            return;
        }

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_imap_close_connection(s->connection);
        }

        return;
    }

    if (rev->active) {
        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_imap_close_connection(s->connection);
        }
    }
}


static ngx_int_t
ngx_imap_auth_http_parse_header_line(ngx_imap_session_t *s,
    ngx_imap_auth_http_ctx_t *ctx)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;
    hash = ctx->hash;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    hash = c;
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    hash = ch;
                    break;
                }

                return NGX_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                hash += c;
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                hash += ch;
                break;
            }

            if (ch >= '0' && ch <= '9') {
                hash += ch;
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NGX_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;
    ctx->hash = hash;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;
    ctx->hash = hash;

    return NGX_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
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

        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_imap_session_internal_server_error(s);
    }
}


static void
ngx_imap_auth_http_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, ev->log, 0,
                   "imap auth http dummy handler");
}


static ngx_buf_t *
ngx_imap_auth_http_create_request(ngx_imap_session_t *s, ngx_pool_t *pool,
    ngx_imap_auth_http_conf_t *ahcf)
{
    size_t      len;
    ngx_buf_t  *b;
    ngx_str_t   login, passwd;

    if (ngx_imap_auth_http_escape(pool, &s->login, &login) != NGX_OK) {
        return NULL;
    }

    if (ngx_imap_auth_http_escape(pool, &s->passwd, &passwd) != NGX_OK) {
        return NULL;
    }

    len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: ") - 1
                + ngx_imap_auth_http_method[s->auth_method].len
                + sizeof(CRLF) - 1
          + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + passwd.len + sizeof(CRLF) - 1
          + sizeof("Auth-Salt: ") - 1 + s->salt.len
          + sizeof("Auth-Protocol: imap" CRLF) - 1
          + sizeof("Auth-Login-Attempt: ") - 1 + NGX_INT_T_LEN
                + sizeof(CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = ngx_cpymem(b->last, "GET ", sizeof("GET ") - 1);
    b->last = ngx_copy(b->last, ahcf->uri.data, ahcf->uri.len);
    b->last = ngx_cpymem(b->last, " HTTP/1.0" CRLF,
                         sizeof(" HTTP/1.0" CRLF) - 1);

    b->last = ngx_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
    b->last = ngx_copy(b->last, ahcf->host_header.data,
                         ahcf->host_header.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Method: ",
                         sizeof("Auth-Method: ") - 1);
    b->last = ngx_cpymem(b->last,
                         ngx_imap_auth_http_method[s->auth_method].data,
                         ngx_imap_auth_http_method[s->auth_method].len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = ngx_copy(b->last, login.data, login.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = ngx_copy(b->last, passwd.data, passwd.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method != NGX_IMAP_AUTH_PLAIN && s->salt.len) {
        b->last = ngx_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
        b->last = ngx_copy(b->last, s->salt.data, s->salt.len);

        s->passwd.data = NULL;
    }

    b->last = ngx_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = ngx_cpymem(b->last, ngx_imap_auth_http_protocol[s->protocol],
                         sizeof("imap") - 1);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
                          s->login_attempt);

    b->last = ngx_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = ngx_copy(b->last, s->connection->addr_text.data,
                         s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    if (ahcf->header.len) {
        b->last = ngx_copy(b->last, ahcf->header.data, ahcf->header.len);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NGX_DEBUG_IMAP_PASSWD)
    {
    ngx_str_t  l;

    l.len = b->last - b->pos;
    l.data = b->pos;
    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                   "imap auth http header:\n\"%V\"", &l);
    }
#endif

    return b;
}


static ngx_int_t
ngx_imap_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text, ngx_str_t *escaped)
{
    u_char      ch, *p;
    ngx_uint_t  i, n;

    n = 0;

    for (i = 0; i < text->len; i++) {
        ch = text->data[i];

        if (ch == CR || ch == LF) {
            n++;
        }
    }

    if (n == 0) {
        *escaped = *text;
        return NGX_OK;
    }

    escaped->len = text->len + n * 2;

    p = ngx_palloc(pool, escaped->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    escaped->data = p;

    for (i = 0; i < text->len; i++) {
        ch = text->data[i];

        if (ch == CR) {
            *p++ = '%';
            *p++ = '0';
            *p++ = 'D';
            continue;
        }

        if (ch == LF) {
            *p++ = '%';
            *p++ = '0';
            *p++ = 'A';
            continue;
        }

        *p++ = ch;
    }

    return NGX_OK;
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

    u_char           *p;
    size_t            len;
    ngx_uint_t        i;
    ngx_table_elt_t  *header;

    if (conf->peer == NULL) {
        conf->peer = prev->peer;
        conf->host_header = prev->host_header;
        conf->uri = prev->uri;
    }

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
        conf->header = prev->header;
    }

    if (conf->headers && conf->header.len == 0) {
        len = 0;
        header = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {
            len += header[i].key.len + 2 + header[i].value.len + 2;
        }

        p = ngx_palloc(cf->pool, len);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->header.len = len;
        conf->header.data = p;

        for (i = 0; i < conf->headers->nelts; i++) {
            p = ngx_cpymem(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = ngx_cpymem(p, header[i].value.data, header[i].value.len);
            *p++ = CR; *p++ = LF;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_imap_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_imap_auth_http_conf_t *ahcf = conf;

    ngx_str_t  *value;
    ngx_url_t   u;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_portn = 80;
    u.uri_part = 1;
    u.one_addr = 1;

    if (ngx_parse_url(cf, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in auth_http \"%V\"", u.err, &u.url);
        }
    }

    ahcf->peer = u.addrs;

    ahcf->host_header = u.host_header;
    ahcf->uri = u.uri;

    if (ahcf->uri.len == 0) {
        ahcf->uri.len = sizeof("/") - 1;
        ahcf->uri.data = (u_char *) "/";
    }

    return NGX_CONF_OK;
}


static char *
ngx_imap_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_imap_auth_http_conf_t *ahcf = conf;

    ngx_str_t        *value;
    ngx_table_elt_t  *header;

    if (ahcf->headers == NULL) {
        ahcf->headers = ngx_array_create(cf->pool, 1, sizeof(ngx_table_elt_t));
        if (ahcf->headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    header = ngx_array_push(ahcf->headers);
    if (header == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    header->key = value[1];
    header->value = value[2];

    return NGX_CONF_OK;
}
