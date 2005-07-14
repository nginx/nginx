
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


static void ngx_imap_init_session(ngx_event_t *rev);
static ngx_int_t ngx_imap_read_command(ngx_imap_session_t *s);


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

static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ OK" CRLF;
static u_char  imap_bye[] = "* BYE" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;


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
        ngx_imap_session_internal_server_error(s);
        return;
    }

    c->data = s;
    s->connection = c;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_imap_max_module);
    if (s->ctx == NULL) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    ctx = c->ctx;
    s->main_conf = ctx->main_conf;
    s->srv_conf = ctx->srv_conf;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
        ngx_imap_session_internal_server_error(s);
        return;
    }

    cscf = ngx_imap_get_module_srv_conf(s, ngx_imap_core_module);

    s->protocol = cscf->protocol;

    if (cscf->protocol == NGX_IMAP_POP3_PROTOCOL) {
        size = 128;
        s->imap_state = ngx_pop3_start;
        c->read->handler = ngx_pop3_auth_state;

    } else {
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
    u_char                    *text, *last, *out, *p;
    ssize_t                    size, text_len, last_len;
    ngx_str_t                 *arg;
    ngx_int_t                  rc;
    ngx_uint_t                 quit, tag;
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

    rc = ngx_imap_read_command(s);

    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap auth: %i", rc);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    quit = 0;
    tag = 1;

    text = NULL;
    text_len = 0;

    last = imap_ok;
    last_len = sizeof(imap_ok) - 1;

    if (rc == NGX_OK) {

        ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0, "imap auth command: %i",
                       s->command);

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

                ngx_log_debug2(NGX_LOG_DEBUG_IMAP, c->log, 0,
                               "imap login:\"%V\" passwd:\"%V\"",
                               &s->login, &s->passwd);

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
            text = imap_bye;
            text_len = sizeof(imap_bye) - 1;
            quit = 1;
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
        if (s->out.len < text_len + s->tag.len + last_len) {

            s->out.len = text_len + s->tag.len + last_len;
            s->out.data = ngx_palloc(c->pool, s->out.len);
            if (s->out.data == NULL) {
                ngx_imap_close_connection(c);
                return;
            }
        }

        out = s->out.data;
        p = out;

        if (text) {
            p = ngx_cpymem(p, text, text_len);
        }
        p = ngx_cpymem(p, s->tag.data, s->tag.len);
        ngx_memcpy(p, last, last_len);

        size = text_len + s->tag.len + last_len;

    } else {
        out = last;
        size = last_len;
    }

    if (ngx_send(c, out, size) < size) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_close_connection(c);
        return;
    }

    if (rc == NGX_IMAP_NEXT) {
        return;
    }

    if (quit) {
        ngx_imap_close_connection(c);
        return;
    }

    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;
    s->tag.len = 0;
}


void
ngx_pop3_auth_state(ngx_event_t *rev)
{
    u_char                    *text;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_uint_t                 quit;
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

    rc = ngx_imap_read_command(s);

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
                quit = 1;
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

                    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                                   "pop3 passwd: \"%V\"", &s->passwd);

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
                quit = 1;
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
ngx_imap_read_command(ngx_imap_session_t *s)
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
