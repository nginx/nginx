
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
} ngx_imap_proxy_conf_t;


static void ngx_imap_proxy_block_read(ngx_event_t *rev);
static void ngx_imap_proxy_auth_handler(ngx_event_t *rev);
static void ngx_imap_proxy_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_imap_proxy_read_response(ngx_imap_session_t *s);
static void ngx_imap_proxy_handler(ngx_event_t *ev);
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
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


void
ngx_imap_proxy_init(ngx_imap_session_t *s, ngx_peers_t *peers)
{
    ngx_int_t              rc;
    ngx_imap_proxy_ctx_t  *p;

    p = ngx_pcalloc(s->connection->pool, sizeof(ngx_imap_proxy_ctx_t));
    if (p == NULL) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    s->proxy = p;

    p->upstream.peers = peers;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&p->upstream);

    if (rc == NGX_ERROR) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_imap_proxy_block_read;
    p->upstream.connection->read->handler = ngx_imap_proxy_auth_handler;
    p->upstream.connection->write->handler = ngx_imap_proxy_dummy_handler;
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
ngx_imap_proxy_auth_handler(ngx_event_t *rev)
{
    u_char              *p;
    ngx_int_t            rc;
    ngx_str_t            line;
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_proxy_close_session(s);
        return;
    }

    if (s->proxy->buffer == NULL) {
        s->proxy->buffer = ngx_create_temp_buf(c->pool, /* STUB */ 4096);
        if (s->proxy->buffer == NULL) {
            ngx_imap_proxy_close_session(s);
            return;
        }
    }

    rc = ngx_imap_proxy_read_response(s);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        /* TODO: ngx_imap_proxy_finalize_session(s, NGX_IMAP_INTERNAL_ERROR) */
        ngx_imap_proxy_close_session(s);
        return;
    }

    if (s->imap_state == ngx_pop3_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy send user");

        line.len = sizeof("USER ") + s->login.len - 1 + 2;
        line.data = ngx_palloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_imap_proxy_close_session(s);
            return;
        }

        p = ngx_cpymem(line.data, "USER ", sizeof("USER ") - 1);
        p = ngx_cpymem(p, s->login.data, s->login.len);
        *p++ = CR; *p = LF;

        if (ngx_send(c, line.data, line.len) < (ssize_t) line.len) {
            /*
             * we treat the incomplete sending as NGX_ERROR
             * because it is very strange here
             */
            ngx_imap_close_connection(c);
            return;
        }

        s->imap_state = ngx_pop3_user;

        s->proxy->buffer->pos = s->proxy->buffer->start;
        s->proxy->buffer->last = s->proxy->buffer->start;

        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy send pass");

    line.len = sizeof("PASS ") + s->passwd.len - 1 + 2;
    line.data = ngx_palloc(c->pool, line.len);
    if (line.data == NULL) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    p = ngx_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
    p = ngx_cpymem(p, s->passwd.data, s->passwd.len);
    *p++ = CR; *p = LF;

    if (ngx_send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_close_connection(c);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;

    s->connection->read->handler = ngx_imap_proxy_handler;
    s->connection->write->handler = ngx_imap_proxy_handler;
    rev->handler = ngx_imap_proxy_handler;
    c->write->handler = ngx_imap_proxy_handler;
}


static void
ngx_imap_proxy_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, ev->log, 0, "imap proxy dummy handler");
}


static ngx_int_t
ngx_imap_proxy_read_response(ngx_imap_session_t *s)
{
    u_char     *p;
    ssize_t     n;
    ngx_buf_t  *b;

    b = s->proxy->buffer;

    n = ngx_recv(s->proxy->upstream.connection, b->last, b->end - b->last);

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

    if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
        return NGX_OK;
    }

    if (p[0] == '-' && p[1] == 'E' && p[2] == 'R' && p[3] == 'R') {
        return NGX_IMAP_PROXY_ERROR;
    }

    *(b->last - 2) = '\0';
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "upstream sent invalid greeting line: \"%s\"", p);

    return NGX_IMAP_PROXY_INVALID;
}


static void
ngx_imap_proxy_handler(ngx_event_t *ev)
{
    size_t               size;
    ssize_t              n;
    ngx_buf_t           *b;
    ngx_uint_t           again, do_write;
    ngx_connection_t    *c, *src, *dst;
    ngx_imap_session_t  *s;

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
                n = ngx_send(dst, b->pos, size);

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
            n = ngx_recv(src, b->last, size);

            if (n == NGX_ERROR || n == 0) {
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
        }

    } while (again);
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

    return pcf;
}


static char *
ngx_imap_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_imap_proxy_conf_t *prev = parent;
    ngx_imap_proxy_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}
