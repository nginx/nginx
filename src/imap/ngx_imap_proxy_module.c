
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_imap.h>


typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  pass_error_message;
    size_t      buffer_size;
    ngx_msec_t  timeout;
} ngx_imap_proxy_conf_t;


static void ngx_imap_proxy_block_read(ngx_event_t *rev);
static void ngx_imap_proxy_imap_handler(ngx_event_t *rev);
static void ngx_imap_proxy_pop3_handler(ngx_event_t *rev);
static void ngx_imap_proxy_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_imap_proxy_read_response(ngx_imap_session_t *s,
    ngx_uint_t state);
static void ngx_imap_proxy_handler(ngx_event_t *ev);
static void ngx_imap_proxy_upstream_error(ngx_imap_session_t *s);
static void ngx_imap_proxy_internal_server_error(ngx_imap_session_t *s);
static void ngx_imap_proxy_close_session(ngx_imap_session_t *s);
static void *ngx_imap_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_imap_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_imap_proxy_commands[] = {

    { ngx_string("proxy"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_proxy_conf_t, enable),
      NULL },

    { ngx_string("proxy_buffer"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_proxy_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_proxy_conf_t, timeout),
      NULL },

    { ngx_string("proxy_pass_error_message"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_proxy_conf_t, pass_error_message),
      NULL },

      ngx_null_command
};


static ngx_imap_module_t  ngx_imap_proxy_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_imap_proxy_create_conf,            /* create server configuration */
    ngx_imap_proxy_merge_conf              /* merge server configuration */
};


ngx_module_t  ngx_imap_proxy_module = {
    NGX_MODULE_V1,
    &ngx_imap_proxy_module_ctx,            /* module context */
    ngx_imap_proxy_commands,               /* module directives */
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


void
ngx_imap_proxy_init(ngx_imap_session_t *s, ngx_peer_addr_t *peer)
{
    int                        keepalive;
    ngx_int_t                  rc;
    ngx_imap_proxy_ctx_t      *p;
    ngx_imap_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);

    if (cscf->so_keepalive) {
        keepalive = 1;

        if (setsockopt(s->connection->fd, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &keepalive, sizeof(int))
                == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, ngx_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed");
        }
    }

    p = ngx_pcalloc(s->connection->pool, sizeof(ngx_imap_proxy_ctx_t));
    if (p == NULL) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.sockaddr = peer->sockaddr;
    p->upstream.socklen = peer->socklen;
    p->upstream.name = &peer->name;
    p->upstream.get = ngx_event_get_peer;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&p->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    ngx_add_timer(p->upstream.connection->read, cscf->timeout);

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_imap_proxy_block_read;
    p->upstream.connection->write->handler = ngx_imap_proxy_dummy_handler;

    if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
        p->upstream.connection->read->handler = ngx_imap_proxy_pop3_handler;
        s->imap_state = ngx_pop3_start;

    } else {
        p->upstream.connection->read->handler = ngx_imap_proxy_imap_handler;
        s->imap_state = ngx_imap_start;
    }
}


static void
ngx_imap_proxy_block_read(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy block read");

    if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
        c = rev->data;
        s = c->data;

        ngx_imap_proxy_close_session(s);
    }
}


static void
ngx_imap_proxy_imap_handler(ngx_event_t *rev)
{
    u_char                 *p;
    ngx_int_t               rc;
    ngx_str_t               line;
    ngx_connection_t       *c;
    ngx_imap_session_t     *s;
    ngx_imap_proxy_conf_t  *pcf;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                   "imap proxy imap auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    if (s->proxy->buffer == NULL) {
        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);

        s->proxy->buffer = ngx_create_temp_buf(c->pool, pcf->buffer_size);
        if (s->proxy->buffer == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }
    }

    rc = ngx_imap_proxy_read_response(s, s->imap_state);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_imap_proxy_upstream_error(s);
        return;
    }

    switch (s->imap_state) {

    case ngx_imap_start:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                       "imap proxy send login");

        s->connection->log->action = "sending LOGIN command to upstream";

        line.len = s->tag.len + sizeof("LOGIN ") - 1
                   + 1 + NGX_SIZE_T_LEN + 1 + 2;
        line.data = ngx_palloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data, "%VLOGIN {%uz}" CRLF,
                               &s->tag, s->login.len)
                   - line.data;

        s->imap_state = ngx_imap_login;
        break;

    case ngx_imap_login:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = s->login.len + 1 + 1 + NGX_SIZE_T_LEN + 1 + 2;
        line.data = ngx_palloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data, "%V {%uz}" CRLF,
                               &s->login, s->passwd.len)
                   - line.data;

        s->imap_state = ngx_imap_user;
        break;

    case ngx_imap_user:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                       "imap proxy send passwd");

        s->connection->log->action = "sending password to upstream";

        line.len = s->passwd.len + 2;
        line.data = ngx_palloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->imap_state = ngx_imap_passwd;
        break;

    case ngx_imap_passwd:
        s->connection->read->handler = ngx_imap_proxy_handler;
        s->connection->write->handler = ngx_imap_proxy_handler;
        rev->handler = ngx_imap_proxy_handler;
        c->write->handler = ngx_imap_proxy_handler;

        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

        ngx_imap_proxy_handler(s->connection->write);

        return;

    default:
#if (NGX_SUPPRESS_WARN)
        line.len = 0;
        line.data = NULL;
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_imap_proxy_pop3_handler(ngx_event_t *rev)
{
    u_char                 *p;
    ngx_int_t               rc;
    ngx_str_t               line;
    ngx_connection_t       *c;
    ngx_imap_session_t     *s;
    ngx_imap_proxy_conf_t  *pcf;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                   "imap proxy pop3 auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    if (s->proxy->buffer == NULL) {
        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);

        s->proxy->buffer = ngx_create_temp_buf(c->pool, pcf->buffer_size);
        if (s->proxy->buffer == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }
    }

    rc = ngx_imap_proxy_read_response(s, 0);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_imap_proxy_upstream_error(s);
        return;
    }

    switch (s->imap_state) {

    case ngx_pop3_start:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = sizeof("USER ")  - 1 + s->login.len + 2;
        line.data = ngx_palloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, "USER ", sizeof("USER ") - 1);
        p = ngx_cpymem(p, s->login.data, s->login.len);
        *p++ = CR; *p = LF;

        s->imap_state = ngx_pop3_user;
        break;

    case ngx_pop3_user:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy send pass");

        s->connection->log->action = "sending password to upstream";

        line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
        line.data = ngx_palloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_imap_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
        p = ngx_cpymem(p, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->imap_state = ngx_pop3_passwd;
        break;

    case ngx_pop3_passwd:
        s->connection->read->handler = ngx_imap_proxy_handler;
        s->connection->write->handler = ngx_imap_proxy_handler;
        rev->handler = ngx_imap_proxy_handler;
        c->write->handler = ngx_imap_proxy_handler;

        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

        ngx_imap_proxy_handler(s->connection->write);

        return;

    default:
#if (NGX_SUPPRESS_WARN)
        line.len = 0;
        line.data = NULL;
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_imap_proxy_dummy_handler(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, wev->log, 0, "imap proxy dummy handler");

    if (ngx_handle_write_event(wev, 0) == NGX_ERROR) {
        c = wev->data;
        s = c->data;

        ngx_imap_proxy_close_session(s);
    }
}


static ngx_int_t
ngx_imap_proxy_read_response(ngx_imap_session_t *s, ngx_uint_t state)
{
    u_char                 *p;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_imap_proxy_conf_t  *pcf;

    s->connection->log->action = "reading response from upstream";

    b = s->proxy->buffer;

    n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
                                            b->last, b->end - b->last);

    if (n == NGX_ERROR || n == 0) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    b->last += n;

    if (b->last - b->pos < 5) {
        return NGX_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    p = b->pos;

    if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
        if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
            return NGX_OK;
        }

    } else {
        switch (state) {

        case ngx_imap_start:
            if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
                return NGX_OK;
            }
            break;

        case ngx_imap_login:
        case ngx_imap_user:
            if (p[0] == '+') {
                return NGX_OK;
            }
            break;

        case ngx_imap_passwd:
            if (ngx_strncmp(p, s->tag.data, s->tag.len) == 0) {
                p += s->tag.len;
                if (p[0] == 'O' && p[1] == 'K') {
                    return NGX_OK;
                }
            }
            break;
        }
    }

    pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);

    if (pcf->pass_error_message == 0) {
        *(b->last - 2) = '\0';
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid response: \"%s\"", p);
        return NGX_ERROR;
    }

    s->out.len = b->last - p - 2;
    s->out.data = p;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "upstream sent invalid response: \"%V\"", &s->out);

    s->out.len = b->last - b->pos;
    s->out.data = b->pos;

    return NGX_ERROR;
}


static void
ngx_imap_proxy_handler(ngx_event_t *ev)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_uint_t              do_write;
    ngx_connection_t       *c, *src, *dst;
    ngx_imap_session_t     *s;
    ngx_imap_proxy_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        c->log->action = "proxying";

        if (c == s->connection) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

        ngx_imap_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        if (ev->write) {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = s->proxy->upstream.connection;
            dst = c;
            b = s->proxy->buffer;

        } else {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = c;
            dst = s->proxy->upstream.connection;
            b = s->buffer;
        }

    } else {
        if (ev->write) {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;

        } else {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = c;
            dst = s->connection;
            b = s->proxy->buffer;
        }
    }

    do_write = ev->write ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_IMAP, ev->log, 0,
                   "imap proxy handler: %d, #%d > #%d",
                   do_write, src->fd, dst->fd);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_imap_proxy_close_session(s);
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
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying";

    if ((s->connection->read->eof || s->proxy->upstream.connection->read->eof)
        && s->buffer->pos == s->buffer->last
        && s->proxy->buffer->pos == s->proxy->buffer->last)
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_imap_proxy_close_session(s);
        return;
    }

    if (ngx_handle_write_event(dst->write, 0) == NGX_ERROR) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    if (ngx_handle_read_event(dst->read, 0) == NGX_ERROR) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    if (ngx_handle_write_event(src->write, 0) == NGX_ERROR) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    if (ngx_handle_read_event(src->read, 0) == NGX_ERROR) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);
        ngx_add_timer(c->read, pcf->timeout);
    }
}


static void
ngx_imap_proxy_upstream_error(ngx_imap_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                       "close imap proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    if (s->out.len == 0) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    s->quit = 1;
    ngx_imap_send(s->connection->write);
}


static void
ngx_imap_proxy_internal_server_error(ngx_imap_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                       "close imap proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_imap_session_internal_server_error(s);
}


static void
ngx_imap_proxy_close_session(ngx_imap_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                       "close imap proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_imap_close_connection(s->connection);
}


static void *
ngx_imap_proxy_create_conf(ngx_conf_t *cf)
{
    ngx_imap_proxy_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_imap_proxy_conf_t));
    if (pcf == NULL) {
        return NGX_CONF_ERROR;
    }

    pcf->enable = NGX_CONF_UNSET;
    pcf->pass_error_message = NGX_CONF_UNSET;
    pcf->buffer_size = NGX_CONF_UNSET_SIZE;
    pcf->timeout = NGX_CONF_UNSET_MSEC;

    return pcf;
}


static char *
ngx_imap_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_imap_proxy_conf_t *prev = parent;
    ngx_imap_proxy_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return NGX_CONF_OK;
}
