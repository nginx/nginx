
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


static void ngx_imap_init_session(ngx_connection_t *c);
static void ngx_imap_init_protocol(ngx_event_t *rev);
static ngx_int_t ngx_imap_read_command(ngx_imap_session_t *s);
static u_char *ngx_imap_log_error(ngx_log_t *log, u_char *buf, size_t len);

#if (NGX_IMAP_SSL)
static void ngx_imap_ssl_handshake_handler(ngx_connection_t *c);
static void ngx_imap_ssl_close_handler(ngx_event_t *ev);
#endif


static ngx_str_t  greetings[] = {
   ngx_string("+OK POP3 ready" CRLF),
   ngx_string("* OK IMAP4 ready" CRLF)
};

static ngx_str_t  internal_server_errors[] = {
   ngx_string("-ERR internal server error" CRLF),
   ngx_string("* BAD internal server error" CRLF),
};

static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;

static u_char  imap_star[] = "* ";
static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ OK" CRLF;
static u_char  imap_bye[] = "* BYE" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;


void
ngx_imap_init_connection(ngx_connection_t *c)
{
    ngx_imap_log_ctx_t        *lctx;
#if (NGX_IMAP_SSL)
    ngx_imap_conf_ctx_t       *ctx;
    ngx_imap_ssl_conf_t       *sslcf;
    ngx_imap_core_srv_conf_t  *cscf;
#endif

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, &c->listening->addr_text);

    lctx = ngx_palloc(c->pool, sizeof(ngx_imap_log_ctx_t));
    if (lctx == NULL) {
        ngx_imap_close_connection(c);
        return;
    } 

    lctx->client = &c->addr_text;
    lctx->session = NULL;

    c->log->connection = c->number;
    c->log->handler = ngx_imap_log_error;
    c->log->data = lctx;
    c->log->action = "sending client greeting line";

    c->log_error = NGX_ERROR_INFO;

#if (NGX_IMAP_SSL)

    ctx = c->ctx;
    sslcf = ngx_imap_get_module_srv_conf(ctx, ngx_imap_ssl_module);

    if (sslcf->enable) {
        if (ngx_ssl_create_connection(&sslcf->ssl, c, 0) == NGX_ERROR) {
            ngx_imap_close_connection(c);
            return;
        }

        if (ngx_ssl_handshake(c) == NGX_AGAIN) {

            cscf = ngx_imap_get_module_srv_conf(ctx, ngx_imap_core_module);

            ngx_add_timer(c->read, cscf->timeout);

            c->ssl->handler = ngx_imap_ssl_handshake_handler;

            return;
        }

        ngx_imap_ssl_handshake_handler(c);
        return;
    }

#endif

    ngx_imap_init_session(c);
}


#if (NGX_IMAP_SSL)

static void
ngx_imap_ssl_handshake_handler(ngx_connection_t *c)
{   
    if (c->ssl->handshaked) {
        ngx_imap_init_session(c);
        return;
    }

    ngx_imap_close_connection(c);
    return;
}

#endif


static void
ngx_imap_init_session(ngx_connection_t *c)
{
    ngx_imap_session_t        *s;
    ngx_imap_log_ctx_t        *lctx;
    ngx_imap_conf_ctx_t       *ctx;
    ngx_imap_core_srv_conf_t  *cscf;

    c->read->handler = ngx_imap_init_protocol;
    c->write->handler = ngx_imap_send;

    s = ngx_pcalloc(c->pool, sizeof(ngx_imap_session_t));
    if (s == NULL) {
        ngx_imap_close_connection(c);
        return;
    }

    ctx = c->ctx;
    cscf = ngx_imap_get_module_srv_conf(ctx, ngx_imap_core_module);

    c->data = s;
    s->connection = c;

    s->protocol = cscf->protocol;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_imap_max_module);
    if (s->ctx == NULL) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    s->main_conf = ctx->main_conf;
    s->srv_conf = ctx->srv_conf;

    s->out = greetings[s->protocol];

    lctx = c->log->data;
    lctx->session = s;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
        ngx_imap_close_connection(c);
    }

    ngx_imap_send(c->write);
}


void
ngx_imap_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_close_connection(c);
        return;
    }

    if (s->out.len == 0) {
        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            ngx_imap_close_connection(c);
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.len -= n;

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        if (s->quit) {
            ngx_imap_close_connection(c);
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_imap_close_connection(c);
        return;
    }

    /* n == NGX_AGAIN */

    cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
        ngx_imap_close_connection(c);
        return;
    }
}


static void
ngx_imap_init_protocol(ngx_event_t *rev)
{
    size_t                     size;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_core_srv_conf_t  *cscf;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_close_connection(c);
        return;
    }

    s = c->data;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
        size = 128;
        s->imap_state = ngx_pop3_start;
        c->read->handler = ngx_pop3_auth_state;

    } else {
        cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);
        size = cscf->imap_client_buffer_size;
        s->imap_state = ngx_imap_start;
        c->read->handler = ngx_imap_auth_state;
    }

    s->buffer = ngx_create_temp_buf(c->pool, size);
    if (s->buffer == NULL) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    c->read->handler(rev);
}


void
ngx_imap_auth_state(ngx_event_t *rev)
{
    u_char                    *text, *last, *p, *dst, *src, *end;
    ssize_t                    text_len, last_len;
    ngx_str_t                 *arg;
    ngx_int_t                  rc;
    ngx_uint_t                 tag, i;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_imap_read_command(s);

    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap auth: %i", rc);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    tag = 1;

    text = NULL;
    text_len = 0;

    last = imap_ok;
    last_len = sizeof(imap_ok) - 1;

    if (rc == NGX_OK) {

        ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap auth command: %i",
                       s->command);

        if (s->backslash) {

            arg = s->args.elts;

            for (i = 0; i < s->args.nelts; i++) {
                dst = arg[i].data;
                end = dst + arg[i].len;

                for (src = dst; src < end; dst++) {
                    *dst = *src;
                    if (*src++ == '\\') {
                        *dst = *src++;
                    }
                }

                arg[i].len = dst - arg[i].data;
            }

            s->backslash = 0;
        }

        switch (s->command) {

        case NGX_IMAP_LOGIN:
            if (s->args.nelts == 2) {

                arg = s->args.elts;

                s->login.len = arg[0].len;
                s->login.data = ngx_palloc(c->pool, s->login.len);
                if (s->login.data == NULL) {
                    ngx_imap_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->login.data, arg[0].data, s->login.len);

                s->passwd.len = arg[1].len;
                s->passwd.data = ngx_palloc(c->pool, s->passwd.len);
                if (s->passwd.data == NULL) {
                    ngx_imap_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

#if (NGX_DEBUG_IMAP_PASSWD)
                ngx_log_debug2(NGX_LOG_DEBUG_IMAP, c->log, 0,
                               "imap login:\"%V\" passwd:\"%V\"",
                               &s->login, &s->passwd);
#else
                ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                               "imap login:\"%V\"", &s->login);
#endif

                s->args.nelts = 0;
                s->buffer->pos = s->buffer->start;
                s->buffer->last = s->buffer->start;

                if (rev->timer_set) {
                    ngx_del_timer(rev);
                }

                s->login_attempt++;

                ngx_imap_auth_http_init(s);

                return;

            } else {
                rc = NGX_IMAP_PARSE_INVALID_COMMAND;
            }

            break;

        case NGX_IMAP_CAPABILITY:
            cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);
            text = cscf->imap_capability->pos;
            text_len = cscf->imap_capability->last - cscf->imap_capability->pos;
            break;

        case NGX_IMAP_LOGOUT:
            s->quit = 1;
            text = imap_bye;
            text_len = sizeof(imap_bye) - 1;
            break;

        case NGX_IMAP_NOOP:
            break;

        default:
            rc = NGX_IMAP_PARSE_INVALID_COMMAND;
            break;
        }

    } else if (rc == NGX_IMAP_NEXT) {
        last = imap_next;
        last_len = sizeof(imap_next) - 1;
        tag = 0;
    }

    if (rc == NGX_IMAP_PARSE_INVALID_COMMAND) {
        last = imap_invalid_command;
        last_len = sizeof(imap_invalid_command) - 1;
    }

    if (tag) {
        if (s->tag.len == 0) {
            s->tag.len = sizeof(imap_star) - 1;
            s->tag.data = (u_char *) imap_star;
        }

        if (s->tagged_line.len < s->tag.len + text_len + last_len) {
            s->tagged_line.len = s->tag.len + text_len + last_len;
            s->tagged_line.data = ngx_palloc(c->pool, s->tagged_line.len);
            if (s->tagged_line.data == NULL) {
                ngx_imap_close_connection(c);
                return;
            }
        }

        s->out.data = s->tagged_line.data;
        s->out.len = s->tag.len + text_len + last_len;

        p = s->out.data;

        if (text) {
            p = ngx_cpymem(p, text, text_len);
        }
        p = ngx_cpymem(p, s->tag.data, s->tag.len);
        ngx_memcpy(p, last, last_len);


    } else {
        s->out.data = last;
        s->out.len = last_len;
    }

    if (rc != NGX_IMAP_NEXT) {
        s->args.nelts = 0;
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
        s->tag.len = 0;
    }

    ngx_imap_send(c->write);
}


void
ngx_pop3_auth_state(ngx_event_t *rev)
{
    u_char                    *text;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_str_t                 *arg;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_imap_read_command(s);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    text = pop3_ok;
    size = sizeof(pop3_ok) - 1;

    if (rc == NGX_OK) {
        switch (s->imap_state) {

        case ngx_pop3_start:

            switch (s->command) {

            case NGX_POP3_USER:
                if (s->args.nelts == 1) {
                    s->imap_state = ngx_pop3_user;

                    arg = s->args.elts;
                    s->login.len = arg[0].len;
                    s->login.data = ngx_palloc(c->pool, s->login.len);
                    if (s->login.data == NULL) {
                        ngx_imap_session_internal_server_error(s);
                        return;
                    }

                    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

                    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                                   "pop3 login: \"%V\"", &s->login);

                } else {
                    rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                }

                break;

            case NGX_POP3_CAPA:
                cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);
                text = cscf->pop3_capability->pos;
                size = cscf->pop3_capability->last - cscf->pop3_capability->pos;
                break;

            case NGX_POP3_QUIT:
                s->quit = 1;
                break;

            case NGX_POP3_NOOP:
                break;

            default:
                s->imap_state = ngx_pop3_start;
                rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_pop3_user:

            switch (s->command) {

            case NGX_POP3_PASS:
                if (s->args.nelts == 1) {
                    /* STUB */ s->imap_state = ngx_pop3_start;

                    arg = s->args.elts;
                    s->passwd.len = arg[0].len;
                    s->passwd.data = ngx_palloc(c->pool, s->passwd.len);
                    if (s->passwd.data == NULL) {
                        ngx_imap_session_internal_server_error(s);
                        return;
                    }

                    ngx_memcpy(s->passwd.data, arg[0].data, s->passwd.len);

#if (NGX_DEBUG_IMAP_PASSWD)
                    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                                   "pop3 passwd: \"%V\"", &s->passwd);
#endif

                    s->args.nelts = 0;
                    s->buffer->pos = s->buffer->start;
                    s->buffer->last = s->buffer->start;

                    if (rev->timer_set) {
                        ngx_del_timer(rev);
                    }

                    ngx_imap_auth_http_init(s);

                    return;

                } else {
                    rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                }

                break;

            case NGX_POP3_CAPA:
                cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);
                text = cscf->pop3_capability->pos;
                size = cscf->pop3_capability->last - cscf->pop3_capability->pos;
                break;

            case NGX_POP3_QUIT:
                s->quit = 1;
                break;

            case NGX_POP3_NOOP:
                break;

            default:
                s->imap_state = ngx_pop3_start;
                rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        /* suppress warinings */
        case ngx_pop3_passwd:
            break;
        }
    }

    if (rc == NGX_IMAP_PARSE_INVALID_COMMAND) {
        text = pop3_invalid_command;
        size = sizeof(pop3_invalid_command) - 1;
    }

    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    s->out.data = text;
    s->out.len = size;

    ngx_imap_send(c->write);
}


static ngx_int_t
ngx_imap_read_command(ngx_imap_session_t *s)
{
    ssize_t    n;
    ngx_int_t  rc;

    n = s->connection->recv(s->connection, s->buffer->last,
                            s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_imap_close_connection(s->connection);
        return NGX_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(s->connection->read, 0) == NGX_ERROR) {
            ngx_imap_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (s->protocol == NGX_IMAP_POP3_PROTOCOL) {
        rc = ngx_pop3_parse_command(s);
    } else {
        rc = ngx_imap_parse_command(s);
    }

    if (rc == NGX_AGAIN
        || rc == NGX_IMAP_NEXT
        || rc == NGX_IMAP_PARSE_INVALID_COMMAND)
    {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_imap_close_connection(s->connection);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_imap_session_internal_server_error(ngx_imap_session_t *s)
{
    s->out = internal_server_errors[s->protocol];
    s->quit = 1;

    ngx_imap_send(s->connection->write);
}


void
ngx_imap_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "close imap connection: %d", c->fd);

#if (NGX_IMAP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->read->handler = ngx_imap_ssl_close_handler;
            c->write->handler = ngx_imap_ssl_close_handler;
            return;
        }
    }

#endif

    c->closed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


#if (NGX_IMAP_SSL)
 
static void
ngx_imap_ssl_close_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, ev->log, 0, "http ssl close handler");

    if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
        return;
    }

    ngx_imap_close_connection(c);
}

#endif


static u_char *
ngx_imap_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_imap_session_t     *s;
    ngx_imap_log_ctx_t     *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }
    
    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V",
                     &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->login.len == 0) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", upstream: %V",
                     &s->proxy->upstream.peers->peer[0].name);

    return p;
}
