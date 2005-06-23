
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>
#include <nginx.h>


static void ngx_imap_init_session(ngx_event_t *rev);

static void ngx_pop3_auth_state(ngx_event_t *rev);
static ngx_int_t ngx_pop3_read_command(ngx_imap_session_t *s);

static void ngx_imap_auth_state(ngx_event_t *rev);


static ngx_str_t  greetings[] = {
   ngx_string("+OK " NGINX_VER " ready" CRLF),
   ngx_string("* OK " NGINX_VER " ready" CRLF)
};

static ngx_str_t  internal_server_errors[] = {
   ngx_string("-ERR internal server error" CRLF),
   ngx_string("* BAD internal server error" CRLF),
};

static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;


void
ngx_imap_init_connection(ngx_connection_t *c)
{
    ssize_t                    size;
    ngx_imap_conf_ctx_t       *ctx;
    ngx_imap_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap init connection");

    c->log_error = NGX_ERROR_INFO;

    ctx = c->ctx;
    cscf = ngx_imap_get_module_srv_conf(ctx, ngx_imap_core_module);

    size = greetings[cscf->protocol].len;

    if (ngx_send(c, greetings[cscf->protocol].data, size) < size) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_close_connection(c);
        return;
    }

    c->read->handler = ngx_imap_init_session;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
        ngx_imap_close_connection(c);
    }
}


static void
ngx_imap_init_session(ngx_event_t *rev)
{
    size_t                     size;
    ngx_connection_t          *c;
    ngx_imap_session_t        *s;
    ngx_imap_conf_ctx_t       *ctx;
    ngx_imap_core_srv_conf_t  *cscf;

    c = rev->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_close_connection(c);
        return;
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_imap_session_t));
    if (s == NULL) {
        ngx_imap_close_connection(c);
        return;
    }

    c->data = s;
    s->connection = c;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_imap_max_module);
    if (s->ctx == NULL) {
        ngx_imap_close_connection(c);
        return;
    }

    ctx = c->ctx;
    s->main_conf = ctx->main_conf;
    s->srv_conf = ctx->srv_conf;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
        ngx_imap_close_connection(c);
        return;
    }

    cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);

    s->protocol = cscf->protocol;

    if (cscf->protocol == NGX_IMAP_POP3_PROTOCOL) {
        size = 128;
        c->read->handler = ngx_pop3_auth_state;

    } else {
        size = cscf->imap_client_buffer_size;
        c->read->handler = ngx_imap_auth_state;
    }

    s->buffer = ngx_create_temp_buf(c->pool, size);
    if (s->buffer == NULL) {
        ngx_imap_close_connection(c);
        return;
    }

    c->read->handler(rev);
}


static void
ngx_imap_auth_state(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    ngx_imap_close_connection(c);
}


static void
ngx_pop3_auth_state(ngx_event_t *rev)
{
    u_char              *text;
    ssize_t              size;
    ngx_int_t            rc;
    ngx_uint_t           quit;
    ngx_str_t           *arg;
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_imap_close_connection(c);
        return;
    }

    rc = ngx_pop3_read_command(s);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    quit = 0;
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
                    s->login.data = ngx_palloc(c->pool, s->login.len + 1);
                    if (s->login.data == NULL) {
                        ngx_imap_close_connection(c);
                        return;
                    }

                    ngx_cpystrn(s->login.data, arg[0].data, s->login.len + 1);

                    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                                   "pop3 login: \"%s\"", s->login.data);

                } else {
                    rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                }

                break;

            case NGX_POP3_QUIT:
                quit = 1;
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
                    s->passwd.data = ngx_palloc(c->pool, s->passwd.len + 1);
                    if (s->passwd.data == NULL) {
                        ngx_imap_close_connection(c);
                        return;
                    }

                    ngx_cpystrn(s->passwd.data, arg[0].data, s->passwd.len + 1);

                    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                                   "pop3 passwd: \"%s\"", s->passwd.data);

                    s->buffer->pos = s->buffer->start;
                    s->buffer->last = s->buffer->start;

                    ngx_imap_auth_http_init(s);

                    return;

                } else {
                    rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                }

                break;

            case NGX_POP3_QUIT:
                quit = 1;
                break;

            default:
                s->imap_state = ngx_pop3_start;
                rc = NGX_IMAP_PARSE_INVALID_COMMAND;
                break;
            }

            break;
        }
    }

    if (rc == NGX_IMAP_PARSE_INVALID_COMMAND) {
        text = pop3_invalid_command;
        size = sizeof(pop3_invalid_command) - 1;
    }

    if (ngx_send(c, text, size) < size) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_close_connection(c);
        return;
    }

    if (quit) {
        ngx_imap_close_connection(c);
        return;
    }

    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;
}


static ngx_int_t
ngx_pop3_read_command(ngx_imap_session_t *s)
{
    ssize_t    n;
    ngx_int_t  rc;

    n = ngx_recv(s->connection, s->buffer->last,
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
            ngx_imap_close_connection(s->connection);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    rc = ngx_pop3_parse_command(s);

    if (rc == NGX_AGAIN || rc == NGX_IMAP_PARSE_INVALID_COMMAND) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_imap_close_connection(s->connection);
        return NGX_ERROR;
    }

    return NGX_OK;
}


#if 0

void
ngx_imap_close_session(ngx_imap_session_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, s->connection->log, 0,
                   "close imap session");

    ngx_imap_close_connection(s->connection);
}

#endif


void
ngx_imap_session_internal_server_error(ngx_imap_session_t *s)
{
    (void) ngx_send(s->connection, internal_server_errors[s->protocol].data,
                    internal_server_errors[s->protocol].len);

    ngx_imap_close_connection(s->connection);
}


void
ngx_imap_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "close imap connection: %d", c->fd);

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}
