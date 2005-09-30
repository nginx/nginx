
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
    size_t      buffer_size;
    ngx_msec_t  timeout;
} ngx_imap_proxy_conf_t;


static void ngx_imap_proxy_block_read(ngx_event_t *rev);
static void ngx_imap_proxy_imap_handler(ngx_event_t *rev);
static void ngx_imap_proxy_pop3_handler(ngx_event_t *rev);
static void ngx_imap_proxy_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_imap_proxy_read_response(ngx_imap_session_t *s,
    ngx_uint_t what);
static void ngx_imap_proxy_handler(ngx_event_t *ev);
static void ngx_imap_proxy_internal_server_error(ngx_imap_session_t *s);
static void ngx_imap_proxy_close_session(ngx_imap_session_t *s);
static void *ngx_imap_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_imap_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


#define NGX_IMAP_WAIT_OK    0
#define NGX_IMAP_WAIT_NEXT  1


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
ngx_imap_proxy_init(ngx_imap_session_t *s, ngx_peers_t *peers)
{
    ngx_int_t                  rc;
    ngx_imap_proxy_ctx_t      *p;
    ngx_imap_core_srv_conf_t  *cscf;

    p = ngx_pcalloc(s->connection->pool, sizeof(ngx_imap_proxy_ctx_t));
    if (p == NULL) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.peers = peers;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NGX_ERROR_ERR;

    s->connection->log->action = "in upstream auth state";

    rc = ngx_event_connect_peer(&p->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);
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
    char                   *action;
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

    rc = ngx_imap_proxy_read_response(s, s->imap_state == ngx_imap_start ?
                                      NGX_IMAP_WAIT_OK : NGX_IMAP_WAIT_NEXT);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR || rc == NGX_IMAP_PROXY_INVALID) {
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    if (rc == NGX_IMAP_PROXY_ERROR) {
        s->connection->read->handler = ngx_imap_proxy_handler;
        s->connection->write->handler = ngx_imap_proxy_handler;
        rev->handler = ngx_imap_proxy_handler;
        c->write->handler = ngx_imap_proxy_handler;

        ngx_imap_proxy_handler(c->read);
        return;
    }

    switch (s->imap_state) {

    case ngx_imap_start:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                       "imap proxy send login");

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

    if (s->imap_state == ngx_imap_passwd) {
        s->connection->read->handler = ngx_imap_proxy_handler;
        s->connection->write->handler = ngx_imap_proxy_handler;
        rev->handler = ngx_imap_proxy_handler;
        c->write->handler = ngx_imap_proxy_handler;

        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");
        c->log->action = action;

        c->log->action = "proxying";
    }
}


static void
ngx_imap_proxy_pop3_handler(ngx_event_t *rev)
{
    char                   *action;
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

    rc = ngx_imap_proxy_read_response(s, NGX_IMAP_WAIT_OK);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR || rc == NGX_IMAP_PROXY_INVALID) {
        ngx_imap_proxy_internal_server_error(s);
        return;
    }

    if (rc == NGX_IMAP_PROXY_ERROR) {
        s->connection->read->handler = ngx_imap_proxy_handler;
        s->connection->write->handler = ngx_imap_proxy_handler;
        rev->handler = ngx_imap_proxy_handler;
        c->write->handler = ngx_imap_proxy_handler;

        ngx_imap_proxy_handler(c->read);
        return;
    }

    switch (s->imap_state) {

    case ngx_pop3_start:
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy send user");

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

    if (s->imap_state == ngx_pop3_passwd) {
        s->connection->read->handler = ngx_imap_proxy_handler;
        s->connection->write->handler = ngx_imap_proxy_handler;
        rev->handler = ngx_imap_proxy_handler;
        c->write->handler = ngx_imap_proxy_handler;

        pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");
        c->log->action = action;

        c->log->action = "proxying";
    }
}


static void
ngx_imap_proxy_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, ev->log, 0, "imap proxy dummy handler");
}


static ngx_int_t
ngx_imap_proxy_read_response(ngx_imap_session_t *s, ngx_uint_t what)
{
    u_char     *p;
    ssize_t     n;
    ngx_buf_t  *b;

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
            return NGX_IMAP_PROXY_INVALID;
        }

        return NGX_AGAIN;
    }

    p = b->pos;

    if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
        if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
            return NGX_OK;
        }

        if (p[0] == '-' && p[1] == 'E' && p[2] == 'R' && p[3] == 'R') {
            return NGX_IMAP_PROXY_ERROR;
        }

    } else {
        if (p[0] == 'N' && p[1] == 'O') {
            return NGX_IMAP_PROXY_ERROR;
        }

        if (what == NGX_IMAP_WAIT_OK) {
            if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
                return NGX_OK;
            }

        } else {
            if (p[0] == '+') {
                return NGX_OK;
            }
        }
    }

    *(b->last - 2) = '\0';
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "upstream sent invalid response: \"%s\"", p);

    return NGX_IMAP_PROXY_INVALID;
}


static void
ngx_imap_proxy_handler(ngx_event_t *ev)
{
    char                   *action;
    size_t                  size;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_uint_t              again, do_write;
    ngx_connection_t       *c, *src, *dst;
    ngx_imap_session_t     *s;
    ngx_imap_proxy_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        if (c == s->connection) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

        ngx_imap_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        if (ev->write) {
            src = s->proxy->upstream.connection;
            dst = c;
            b = s->proxy->buffer;

        } else {
            src = c;
            dst = s->proxy->upstream.connection;
            b = s->buffer;
        }

    } else {
        if (ev->write) {
            src = s->connection;
            dst = c;
            b = s->buffer;

        } else {
            src = c;
            dst = s->connection;
            b = s->proxy->buffer;
        }
    }

    do_write = ev->write ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_IMAP, ev->log, 0,
                   "imap proxy handler: %d, #%d > #%d",
                   do_write, src->fd, dst->fd);

    do {
        again = 0;

        if (do_write == 1) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_imap_proxy_close_session(s);
                    return;
                }

                if (n > 0) {
                    again = 1;
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }

                if (n == NGX_AGAIN || n < (ssize_t) size) {
                    if (ngx_handle_write_event(dst->write, /* TODO: LOWAT */ 0)
                        == NGX_ERROR)
                    {
                        ngx_imap_proxy_close_session(s);
                        return;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {
            n = src->recv(src, b->last, size);

            if (n == NGX_ERROR) {
                ngx_imap_proxy_close_session(s);
                return;
            }

            if (n == 0) {
                action = c->log->action;
                c->log->action = NULL;
                ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
                c->log->action = action;

                ngx_imap_proxy_close_session(s);
                return;
            }

            if (n > 0) {
                again = 1;
                do_write = 1;
                b->last += n;
            }

            if (n == NGX_AGAIN || n < (ssize_t) size) {
                if (ngx_handle_read_event(src->read, 0) == NGX_ERROR) {
                    ngx_imap_proxy_close_session(s);
                    return;
                }
            }

            if (c == s->connection) {
                pcf = ngx_imap_get_module_srv_conf(s, ngx_imap_proxy_module);
                ngx_add_timer(c->read, pcf->timeout);
            }
        }

    } while (again);
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
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return NGX_CONF_OK;
}
