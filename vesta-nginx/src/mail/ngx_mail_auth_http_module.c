
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_mail.h>


typedef struct {
    ngx_addr_t                     *peer;

    ngx_msec_t                      timeout;
    ngx_flag_t                      pass_client_cert;

    ngx_str_t                       host_header;
    ngx_str_t                       uri;
    ngx_str_t                       header;

    ngx_array_t                    *headers;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_mail_auth_http_conf_t;


typedef struct ngx_mail_auth_http_ctx_s  ngx_mail_auth_http_ctx_t;

typedef void (*ngx_mail_auth_http_handler_pt)(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);

struct ngx_mail_auth_http_ctx_s {
    ngx_buf_t                      *request;
    ngx_buf_t                      *response;
    ngx_peer_connection_t           peer;

    ngx_mail_auth_http_handler_pt   handler;

    ngx_uint_t                      state;

    u_char                         *header_name_start;
    u_char                         *header_name_end;
    u_char                         *header_start;
    u_char                         *header_end;

    ngx_str_t                       addr;
    ngx_str_t                       port;
    ngx_str_t                       err;
    ngx_str_t                       errmsg;
    ngx_str_t                       errcode;

    time_t                          sleep;

    ngx_pool_t                     *pool;
};


static void ngx_mail_auth_http_write_handler(ngx_event_t *wev);
static void ngx_mail_auth_http_read_handler(ngx_event_t *rev);
static void ngx_mail_auth_http_ignore_status_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_auth_http_process_headers(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_auth_sleep_handler(ngx_event_t *rev);
static ngx_int_t ngx_mail_auth_http_parse_header_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_auth_http_block_read(ngx_event_t *rev);
static void ngx_mail_auth_http_dummy_handler(ngx_event_t *ev);
static ngx_buf_t *ngx_mail_auth_http_create_request(ngx_mail_session_t *s,
    ngx_pool_t *pool, ngx_mail_auth_http_conf_t *ahcf);
static ngx_int_t ngx_mail_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text,
    ngx_str_t *escaped);

static void *ngx_mail_auth_http_create_conf(ngx_conf_t *cf);
static char *ngx_mail_auth_http_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_mail_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_mail_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_mail_auth_http_commands[] = {

    { ngx_string("auth_http"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_mail_auth_http,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_http_timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_auth_http_conf_t, timeout),
      NULL },

    { ngx_string("auth_http_header"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE2,
      ngx_mail_auth_http_header,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_http_pass_client_cert"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_auth_http_conf_t, pass_client_cert),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_auth_http_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_auth_http_create_conf,        /* create server configuration */
    ngx_mail_auth_http_merge_conf          /* merge server configuration */
};


ngx_module_t  ngx_mail_auth_http_module = {
    NGX_MODULE_V1,
    &ngx_mail_auth_http_module_ctx,        /* module context */
    ngx_mail_auth_http_commands,           /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t   ngx_mail_auth_http_method[] = {
    ngx_string("plain"),
    ngx_string("plain"),
    ngx_string("plain"),
    ngx_string("apop"),
    ngx_string("cram-md5"),
    ngx_string("none")
};

static ngx_str_t   ngx_mail_smtp_errcode = ngx_string("535 5.7.0");


void
ngx_mail_auth_http_init(ngx_mail_session_t *s)
{
    ngx_int_t                   rc;
    ngx_pool_t                 *pool;
    ngx_mail_auth_http_ctx_t   *ctx;
    ngx_mail_auth_http_conf_t  *ahcf;

    s->connection->log->action = "in http auth state";

    pool = ngx_create_pool(2048, s->connection->log);
    if (pool == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_mail_auth_http_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx->pool = pool;

    ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);

    ctx->request = ngx_mail_auth_http_create_request(s, pool, ahcf);
    if (ctx->request == NULL) {
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ngx_mail_set_ctx(s, ctx, ngx_mail_auth_http_module);

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
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_mail_auth_http_block_read;
    ctx->peer.connection->read->handler = ngx_mail_auth_http_read_handler;
    ctx->peer.connection->write->handler = ngx_mail_auth_http_write_handler;

    ctx->handler = ngx_mail_auth_http_ignore_status_line;

    ngx_add_timer(ctx->peer.connection->read, ahcf->timeout);
    ngx_add_timer(ctx->peer.connection->write, ahcf->timeout);

    if (rc == NGX_OK) {
        ngx_mail_auth_http_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
ngx_mail_auth_http_write_handler(ngx_event_t *wev)
{
    ssize_t                     n, size;
    ngx_connection_t           *c;
    ngx_mail_session_t         *s;
    ngx_mail_auth_http_ctx_t   *ctx;
    ngx_mail_auth_http_conf_t  *ahcf;

    c = wev->data;
    s = c->data;

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0,
                   "mail auth http write handler");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = ngx_send(c, ctx->request->pos, size);

    if (n == NGX_ERROR) {
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = ngx_mail_auth_http_dummy_handler;

            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_close_connection(c);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);
        ngx_add_timer(wev, ahcf->timeout);
    }
}


static void
ngx_mail_auth_http_read_handler(ngx_event_t *rev)
{
    ssize_t                     n, size;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_auth_http_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http read handler");

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, 1024);
        if (ctx->response == NULL) {
            ngx_close_connection(c);
            ngx_destroy_pool(ctx->pool);
            ngx_mail_session_internal_server_error(s);
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

    ngx_close_connection(c);
    ngx_destroy_pool(ctx->pool);
    ngx_mail_session_internal_server_error(s);
}


static void
ngx_mail_auth_http_ignore_status_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx)
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

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process status line");

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
            ngx_mail_session_internal_server_error(s);
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
    ctx->handler = ngx_mail_auth_http_process_headers;
    ctx->handler(s, ctx);
}


static void
ngx_mail_auth_http_process_headers(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx)
{
    u_char               *p;
    time_t                timer;
    size_t                len, size;
    ngx_int_t             rc, port, n;
    ngx_addr_t           *peer;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process headers");

    for ( ;; ) {
        rc = ngx_mail_auth_http_parse_header_line(s, ctx);

        if (rc == NGX_OK) {

#if (NGX_DEBUG)
            {
            ngx_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Status",
                                   sizeof("Auth-Status") - 1)
                   == 0)
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

                switch (s->protocol) {

                case NGX_MAIL_POP3_PROTOCOL:
                    size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;
                    break;

                case NGX_MAIL_IMAP_PROTOCOL:
                    size = s->tag.len + sizeof("NO ") - 1 + len
                           + sizeof(CRLF) - 1;
                    break;

                default: /* NGX_MAIL_SMTP_PROTOCOL */
                    ctx->err = ctx->errmsg;
                    continue;
                }

                p = ngx_pnalloc(s->connection->pool, size);
                if (p == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ctx->err.data = p;

                switch (s->protocol) {

                case NGX_MAIL_POP3_PROTOCOL:
                    *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R'; *p++ = ' ';
                    break;

                case NGX_MAIL_IMAP_PROTOCOL:
                    p = ngx_cpymem(p, s->tag.data, s->tag.len);
                    *p++ = 'N'; *p++ = 'O'; *p++ = ' ';
                    break;

                default: /* NGX_MAIL_SMTP_PROTOCOL */
                    break;
                }

                p = ngx_cpymem(p, ctx->header_start, len);
                *p++ = CR; *p++ = LF;

                ctx->err.len = p - ctx->err.data;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Server",
                                   sizeof("Auth-Server") - 1)
                    == 0)
            {
                ctx->addr.len = ctx->header_end - ctx->header_start;
                ctx->addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Port",
                                   sizeof("Auth-Port") - 1)
                   == 0)
            {
                ctx->port.len = ctx->header_end - ctx->header_start;
                ctx->port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-User") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-User",
                                   sizeof("Auth-User") - 1)
                   == 0)
            {
                s->login.len = ctx->header_end - ctx->header_start;

                s->login.data = ngx_pnalloc(s->connection->pool, s->login.len);
                if (s->login.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->login.data, ctx->header_start, s->login.len);

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Pass",
                                   sizeof("Auth-Pass") - 1)
                   == 0)
            {
                s->passwd.len = ctx->header_end - ctx->header_start;

                s->passwd.data = ngx_pnalloc(s->connection->pool,
                                             s->passwd.len);
                if (s->passwd.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);

                continue;
            }

            if (len == sizeof("Auth-Wait") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Wait",
                                   sizeof("Auth-Wait") - 1)
                   == 0)
            {
                n = ngx_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != NGX_ERROR) {
                    ctx->sleep = n;
                }

                continue;
            }

            if (len == sizeof("Auth-Error-Code") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Error-Code",
                                   sizeof("Auth-Error-Code") - 1)
                   == 0)
            {
                ctx->errcode.len = ctx->header_end - ctx->header_start;

                ctx->errcode.data = ngx_pnalloc(s->connection->pool,
                                                ctx->errcode.len);
                if (ctx->errcode.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(ctx->errcode.data, ctx->header_start,
                           ctx->errcode.len);

                continue;
            }

            /* ignore other headers */

            continue;
        }

        if (rc == NGX_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header done");

            ngx_close_connection(ctx->peer.connection);

            if (ctx->err.len) {

                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "client login failed: \"%V\"", &ctx->errmsg);

                if (s->protocol == NGX_MAIL_SMTP_PROTOCOL) {

                    if (ctx->errcode.len == 0) {
                        ctx->errcode = ngx_mail_smtp_errcode;
                    }

                    ctx->err.len = ctx->errcode.len + ctx->errmsg.len
                                   + sizeof(" " CRLF) - 1;

                    p = ngx_pnalloc(s->connection->pool, ctx->err.len);
                    if (p == NULL) {
                        ngx_destroy_pool(ctx->pool);
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    ctx->err.data = p;

                    p = ngx_cpymem(p, ctx->errcode.data, ctx->errcode.len);
                    *p++ = ' ';
                    p = ngx_cpymem(p, ctx->errmsg.data, ctx->errmsg.len);
                    *p++ = CR; *p = LF;
                }

                s->out = ctx->err;
                timer = ctx->sleep;

                ngx_destroy_pool(ctx->pool);

                if (timer == 0) {
                    s->quit = 1;
                    ngx_mail_send(s->connection->write);
                    return;
                }

                ngx_add_timer(s->connection->read, (ngx_msec_t) (timer * 1000));

                s->connection->read->handler = ngx_mail_auth_sleep_handler;

                return;
            }

            if (s->auth_wait) {
                timer = ctx->sleep;

                ngx_destroy_pool(ctx->pool);

                if (timer == 0) {
                    ngx_mail_auth_http_init(s);
                    return;
                }

                ngx_add_timer(s->connection->read, (ngx_msec_t) (timer * 1000));

                s->connection->read->handler = ngx_mail_auth_sleep_handler;

                return;
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send server or port",
                              ctx->peer.name);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (s->passwd.data == NULL
                && s->protocol != NGX_MAIL_SMTP_PROTOCOL)
            {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send password",
                              ctx->peer.name);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            peer = ngx_pcalloc(s->connection->pool, sizeof(ngx_addr_t));
            if (peer == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            rc = ngx_parse_addr(s->connection->pool, peer,
                                ctx->addr.data, ctx->addr.len);

            switch (rc) {
            case NGX_OK:
                break;

            case NGX_DECLINED:
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "address:\"%V\"",
                              ctx->peer.name, &ctx->addr);
                /* fall through */

            default:
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            port = ngx_atoi(ctx->port.data, ctx->port.len);
            if (port == NGX_ERROR || port < 1 || port > 65535) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "port:\"%V\"",
                              ctx->peer.name, &ctx->port);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            switch (peer->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) peer->sockaddr;
                sin6->sin6_port = htons((in_port_t) port);
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) peer->sockaddr;
                sin->sin_port = htons((in_port_t) port);
                break;
            }

            len = ctx->addr.len + 1 + ctx->port.len;

            peer->name.len = len;

            peer->name.data = ngx_pnalloc(s->connection->pool, len);
            if (peer->name.data == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            len = ctx->addr.len;

            ngx_memcpy(peer->name.data, ctx->addr.data, len);

            peer->name.data[len++] = ':';

            ngx_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);

            ngx_destroy_pool(ctx->pool);
            ngx_mail_proxy_init(s, peer);

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
        ngx_mail_session_internal_server_error(s);

        return;
    }
}


static void
ngx_mail_auth_sleep_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail auth sleep handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {

        rev->timedout = 0;

        if (s->auth_wait) {
            s->auth_wait = 0;
            ngx_mail_auth_http_init(s);
            return;
        }

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        rev->handler = cscf->protocol->auth_state;

        s->mail_state = 0;
        s->auth_method = NGX_MAIL_AUTH_PLAIN;

        c->log->action = "in auth state";

        ngx_mail_send(c->write);

        if (c->destroyed) {
            return;
        }

        ngx_add_timer(rev, cscf->timeout);

        if (rev->ready) {
            rev->handler(rev);
            return;
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_mail_close_connection(c);
        }

        return;
    }

    if (rev->active) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_mail_close_connection(c);
        }
    }
}


static ngx_int_t
ngx_mail_auth_http_parse_header_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx)
{
    u_char      c, ch, *p;
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
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NGX_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
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

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
}


static void
ngx_mail_auth_http_block_read(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_auth_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);

        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
    }
}


static void
ngx_mail_auth_http_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail auth http dummy handler");
}


static ngx_buf_t *
ngx_mail_auth_http_create_request(ngx_mail_session_t *s, ngx_pool_t *pool,
    ngx_mail_auth_http_conf_t *ahcf)
{
    size_t                     len;
    ngx_buf_t                 *b;
    ngx_str_t                  login, passwd;
#if (NGX_MAIL_SSL)
    ngx_str_t                  verify, subject, issuer, serial, fingerprint,
                               raw_cert, cert;
    ngx_connection_t          *c;
    ngx_mail_ssl_conf_t       *sslcf;
#endif
    ngx_mail_core_srv_conf_t  *cscf;

    if (ngx_mail_auth_http_escape(pool, &s->login, &login) != NGX_OK) {
        return NULL;
    }

    if (ngx_mail_auth_http_escape(pool, &s->passwd, &passwd) != NGX_OK) {
        return NULL;
    }

#if (NGX_MAIL_SSL)

    c = s->connection;
    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (c->ssl && sslcf->verify) {

        /* certificate details */

        if (ngx_ssl_get_client_verify(c, pool, &verify) != NGX_OK) {
            return NULL;
        }

        if (ngx_ssl_get_subject_dn(c, pool, &subject) != NGX_OK) {
            return NULL;
        }

        if (ngx_ssl_get_issuer_dn(c, pool, &issuer) != NGX_OK) {
            return NULL;
        }

        if (ngx_ssl_get_serial_number(c, pool, &serial) != NGX_OK) {
            return NULL;
        }

        if (ngx_ssl_get_fingerprint(c, pool, &fingerprint) != NGX_OK) {
            return NULL;
        }

        if (ahcf->pass_client_cert) {

            /* certificate itself, if configured */

            if (ngx_ssl_get_raw_certificate(c, pool, &raw_cert) != NGX_OK) {
                return NULL;
            }

            if (ngx_mail_auth_http_escape(pool, &raw_cert, &cert) != NGX_OK) {
                return NULL;
            }

        } else {
            ngx_str_null(&cert);
        }

    } else {
        ngx_str_null(&verify);
        ngx_str_null(&subject);
        ngx_str_null(&issuer);
        ngx_str_null(&serial);
        ngx_str_null(&fingerprint);
        ngx_str_null(&cert);
    }

#endif

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: ") - 1
                + ngx_mail_auth_http_method[s->auth_method].len
                + sizeof(CRLF) - 1
          + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + passwd.len + sizeof(CRLF) - 1
          + sizeof("Auth-Salt: ") - 1 + s->salt.len
          + sizeof("Auth-Protocol: ") - 1 + cscf->protocol->name.len
                + sizeof(CRLF) - 1
          + sizeof("Auth-Login-Attempt: ") - 1 + NGX_INT_T_LEN
                + sizeof(CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof("Client-Host: ") - 1 + s->host.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-Helo: ") - 1 + s->smtp_helo.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-From: ") - 1 + s->smtp_from.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-To: ") - 1 + s->smtp_to.len + sizeof(CRLF) - 1
#if (NGX_MAIL_SSL)
          + sizeof("Auth-SSL: on" CRLF) - 1
          + sizeof("Auth-SSL-Verify: ") - 1 + verify.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Subject: ") - 1 + subject.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Issuer: ") - 1 + issuer.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Serial: ") - 1 + serial.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Fingerprint: ") - 1 + fingerprint.len
              + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Cert: ") - 1 + cert.len + sizeof(CRLF) - 1
#endif
          + ahcf->header.len
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
                         ngx_mail_auth_http_method[s->auth_method].data,
                         ngx_mail_auth_http_method[s->auth_method].len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = ngx_copy(b->last, login.data, login.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = ngx_copy(b->last, passwd.data, passwd.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method != NGX_MAIL_AUTH_PLAIN && s->salt.len) {
        b->last = ngx_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
        b->last = ngx_copy(b->last, s->salt.data, s->salt.len);

        s->passwd.data = NULL;
    }

    b->last = ngx_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = ngx_cpymem(b->last, cscf->protocol->name.data,
                         cscf->protocol->name.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
                          s->login_attempt);

    b->last = ngx_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = ngx_copy(b->last, s->connection->addr_text.data,
                       s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->host.len) {
        b->last = ngx_cpymem(b->last, "Client-Host: ",
                             sizeof("Client-Host: ") - 1);
        b->last = ngx_copy(b->last, s->host.data, s->host.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    if (s->auth_method == NGX_MAIL_AUTH_NONE) {

        /* HELO, MAIL FROM, and RCPT TO can't contain CRLF, no need to escape */

        b->last = ngx_cpymem(b->last, "Auth-SMTP-Helo: ",
                             sizeof("Auth-SMTP-Helo: ") - 1);
        b->last = ngx_copy(b->last, s->smtp_helo.data, s->smtp_helo.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = ngx_cpymem(b->last, "Auth-SMTP-From: ",
                             sizeof("Auth-SMTP-From: ") - 1);
        b->last = ngx_copy(b->last, s->smtp_from.data, s->smtp_from.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = ngx_cpymem(b->last, "Auth-SMTP-To: ",
                             sizeof("Auth-SMTP-To: ") - 1);
        b->last = ngx_copy(b->last, s->smtp_to.data, s->smtp_to.len);
        *b->last++ = CR; *b->last++ = LF;

    }

#if (NGX_MAIL_SSL)

    if (c->ssl) {
        b->last = ngx_cpymem(b->last, "Auth-SSL: on" CRLF,
                             sizeof("Auth-SSL: on" CRLF) - 1);

        if (verify.len) {
            b->last = ngx_cpymem(b->last, "Auth-SSL-Verify: ",
                                 sizeof("Auth-SSL-Verify: ") - 1);
            b->last = ngx_copy(b->last, verify.data, verify.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (subject.len) {
            b->last = ngx_cpymem(b->last, "Auth-SSL-Subject: ",
                                 sizeof("Auth-SSL-Subject: ") - 1);
            b->last = ngx_copy(b->last, subject.data, subject.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (issuer.len) {
            b->last = ngx_cpymem(b->last, "Auth-SSL-Issuer: ",
                                 sizeof("Auth-SSL-Issuer: ") - 1);
            b->last = ngx_copy(b->last, issuer.data, issuer.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (serial.len) {
            b->last = ngx_cpymem(b->last, "Auth-SSL-Serial: ",
                                 sizeof("Auth-SSL-Serial: ") - 1);
            b->last = ngx_copy(b->last, serial.data, serial.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (fingerprint.len) {
            b->last = ngx_cpymem(b->last, "Auth-SSL-Fingerprint: ",
                                 sizeof("Auth-SSL-Fingerprint: ") - 1);
            b->last = ngx_copy(b->last, fingerprint.data, fingerprint.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (cert.len) {
            b->last = ngx_cpymem(b->last, "Auth-SSL-Cert: ",
                                 sizeof("Auth-SSL-Cert: ") - 1);
            b->last = ngx_copy(b->last, cert.data, cert.len);
            *b->last++ = CR; *b->last++ = LF;
        }
    }

#endif

    if (ahcf->header.len) {
        b->last = ngx_copy(b->last, ahcf->header.data, ahcf->header.len);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);
#endif

    return b;
}


static ngx_int_t
ngx_mail_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text, ngx_str_t *escaped)
{
    u_char     *p;
    uintptr_t   n;

    n = ngx_escape_uri(NULL, text->data, text->len, NGX_ESCAPE_MAIL_AUTH);

    if (n == 0) {
        *escaped = *text;
        return NGX_OK;
    }

    escaped->len = text->len + n * 2;

    p = ngx_pnalloc(pool, escaped->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_escape_uri(p, text->data, text->len, NGX_ESCAPE_MAIL_AUTH);

    escaped->data = p;

    return NGX_OK;
}


static void *
ngx_mail_auth_http_create_conf(ngx_conf_t *cf)
{
    ngx_mail_auth_http_conf_t  *ahcf;

    ahcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_auth_http_conf_t));
    if (ahcf == NULL) {
        return NULL;
    }

    ahcf->timeout = NGX_CONF_UNSET_MSEC;
    ahcf->pass_client_cert = NGX_CONF_UNSET;

    ahcf->file = cf->conf_file->file.name.data;
    ahcf->line = cf->conf_file->line;

    return ahcf;
}


static char *
ngx_mail_auth_http_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_auth_http_conf_t *prev = parent;
    ngx_mail_auth_http_conf_t *conf = child;

    u_char           *p;
    size_t            len;
    ngx_uint_t        i;
    ngx_table_elt_t  *header;

    if (conf->peer == NULL) {
        conf->peer = prev->peer;
        conf->host_header = prev->host_header;
        conf->uri = prev->uri;

        if (conf->peer == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"auth_http\" is defined for server in %s:%ui",
                          conf->file, conf->line);

            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    ngx_conf_merge_value(conf->pass_client_cert, prev->pass_client_cert, 0);

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

        p = ngx_pnalloc(cf->pool, len);
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
ngx_mail_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_auth_http_conf_t *ahcf = conf;

    ngx_str_t  *value;
    ngx_url_t   u;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 80;
    u.uri_part = 1;

    if (ngx_strncmp(u.url.data, "http://", 7) == 0) {
        u.url.len -= 7;
        u.url.data += 7;
    }

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in auth_http \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    ahcf->peer = u.addrs;

    if (u.family != AF_UNIX) {
        ahcf->host_header = u.host;

    } else {
        ngx_str_set(&ahcf->host_header, "localhost");
    }

    ahcf->uri = u.uri;

    if (ahcf->uri.len == 0) {
        ngx_str_set(&ahcf->uri, "/");
    }

    return NGX_CONF_OK;
}


static char *
ngx_mail_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_auth_http_conf_t *ahcf = conf;

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
