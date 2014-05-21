
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_smtp_module.h>


static void ngx_mail_smtp_resolve_addr_handler(ngx_resolver_ctx_t *ctx);
static void ngx_mail_smtp_resolve_name(ngx_event_t *rev);
static void ngx_mail_smtp_resolve_name_handler(ngx_resolver_ctx_t *ctx);
static void ngx_mail_smtp_greeting(ngx_mail_session_t *s, ngx_connection_t *c);
static void ngx_mail_smtp_invalid_pipelining(ngx_event_t *rev);
static ngx_int_t ngx_mail_smtp_create_buffer(ngx_mail_session_t *s,
    ngx_connection_t *c);

static ngx_int_t ngx_mail_smtp_helo(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_auth(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_mail(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_starttls(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_rset(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_rcpt(ngx_mail_session_t *s, ngx_connection_t *c);

static ngx_int_t ngx_mail_smtp_discard_command(ngx_mail_session_t *s,
    ngx_connection_t *c, char *err);
static void ngx_mail_smtp_log_rejected_command(ngx_mail_session_t *s,
    ngx_connection_t *c, char *err);


static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char  smtp_next[] = "334 " CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char  smtp_invalid_pipelining[] =
   "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
static u_char  smtp_bad_sequence[] = "503 5.5.1 Bad sequence of commands" CRLF;


static ngx_str_t  smtp_unavailable = ngx_string("[UNAVAILABLE]");
static ngx_str_t  smtp_tempunavail = ngx_string("[TEMPUNAVAIL]");


void
ngx_mail_smtp_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_resolver_ctx_t        *ctx;
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (cscf->resolver == NULL) {
        s->host = smtp_unavailable;
        ngx_mail_smtp_greeting(s, c);
        return;
    }

#if (NGX_HAVE_UNIX_DOMAIN)
    if (c->sockaddr->sa_family == AF_UNIX) {
        s->host = smtp_tempunavail;
        ngx_mail_smtp_greeting(s, c);
        return;
    }
#endif

    c->log->action = "in resolving client address";

    ctx = ngx_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    ctx->addr.sockaddr = c->sockaddr;
    ctx->addr.socklen = c->socklen;
    ctx->handler = ngx_mail_smtp_resolve_addr_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    if (ngx_resolve_addr(ctx) != NGX_OK) {
        ngx_mail_close_connection(c);
    }
}


static void
ngx_mail_smtp_resolve_addr_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &c->addr_text, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

        ngx_resolve_addr_done(ctx);

        ngx_mail_smtp_greeting(s, s->connection);

        return;
    }

    c->log->action = "in resolving client hostname";

    s->host.data = ngx_pstrdup(c->pool, &ctx->name);
    if (s->host.data == NULL) {
        ngx_resolve_addr_done(ctx);
        ngx_mail_close_connection(c);
        return;
    }

    s->host.len = ctx->name.len;

    ngx_resolve_addr_done(ctx);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "address resolved: %V", &s->host);

    c->read->handler = ngx_mail_smtp_resolve_name;

    ngx_post_event(c->read, &ngx_posted_events);
}


static void
ngx_mail_smtp_resolve_name(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_resolver_ctx_t        *ctx;
    ngx_mail_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ctx = ngx_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    ctx->name = s->host;
    ctx->handler = ngx_mail_smtp_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_mail_close_connection(c);
    }
}


static void
ngx_mail_smtp_resolve_name_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_uint_t           i;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "\"%V\" could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

    } else {

#if (NGX_DEBUG)
        {
        u_char     text[NGX_SOCKADDR_STRLEN];
        ngx_str_t  addr;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            addr.len = ngx_sock_ntop(ctx->addrs[i].sockaddr,
                                     ctx->addrs[i].socklen,
                                     text, NGX_SOCKADDR_STRLEN, 0);

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "name was resolved to %V", &addr);
        }
        }
#endif

        for (i = 0; i < ctx->naddrs; i++) {
            if (ngx_cmp_sockaddr(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                 c->sockaddr, c->socklen, 0)
                == NGX_OK)
            {
                goto found;
            }
        }

        s->host = smtp_unavailable;
    }

found:

    ngx_resolve_name_done(ctx);

    ngx_mail_smtp_greeting(s, c);
}


static void
ngx_mail_smtp_greeting(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_msec_t                 timeout;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_smtp_srv_conf_t  *sscf;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp greeting for \"%V\"", &s->host);

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_mail_close_connection(c);
    }

    if (sscf->greeting_delay) {
         c->read->handler = ngx_mail_smtp_invalid_pipelining;
         return;
    }

    c->read->handler = ngx_mail_smtp_init_protocol;

    s->out = sscf->greeting;

    ngx_mail_send(c->write);
}


static void
ngx_mail_smtp_invalid_pipelining(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_smtp_srv_conf_t  *sscf;

    c = rev->data;
    s = c->data;

    c->log->action = "in delay pipelining state";

    if (rev->timedout) {

        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "delay greeting");

        rev->timedout = 0;

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        c->read->handler = ngx_mail_smtp_init_protocol;

        ngx_add_timer(c->read, cscf->timeout);

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_mail_close_connection(c);
            return;
        }

        sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);

        s->out = sscf->greeting;

    } else {

        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "invalid pipelining");

        if (s->buffer == NULL) {
            if (ngx_mail_smtp_create_buffer(s, c) != NGX_OK) {
                return;
            }
        }

        if (ngx_mail_smtp_discard_command(s, c,
                                "client was rejected before greeting: \"%V\"")
            != NGX_OK)
        {
            return;
        }

        ngx_str_set(&s->out, smtp_invalid_pipelining);
        s->quit = 1;
    }

    ngx_mail_send(c->write);
}


void
ngx_mail_smtp_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (ngx_mail_smtp_create_buffer(s, c) != NGX_OK) {
            return;
        }
    }

    s->mail_state = ngx_smtp_start;
    c->read->handler = ngx_mail_smtp_auth_state;

    ngx_mail_smtp_auth_state(rev);
}


static ngx_int_t
ngx_mail_smtp_create_buffer(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_smtp_srv_conf_t  *sscf;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
        ngx_mail_session_internal_server_error(s);
        return NGX_ERROR;
    }

    sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);

    s->buffer = ngx_create_temp_buf(c->pool, sscf->client_buffer_size);
    if (s->buffer == NULL) {
        ngx_mail_session_internal_server_error(s);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_mail_smtp_auth_state(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    ngx_str_set(&s->out, smtp_ok);

    if (rc == NGX_OK) {
        switch (s->mail_state) {

        case ngx_smtp_start:

            switch (s->command) {

            case NGX_SMTP_HELO:
            case NGX_SMTP_EHLO:
                rc = ngx_mail_smtp_helo(s, c);
                break;

            case NGX_SMTP_AUTH:
                rc = ngx_mail_smtp_auth(s, c);
                break;

            case NGX_SMTP_QUIT:
                s->quit = 1;
                ngx_str_set(&s->out, smtp_bye);
                break;

            case NGX_SMTP_MAIL:
                rc = ngx_mail_smtp_mail(s, c);
                break;

            case NGX_SMTP_RCPT:
                rc = ngx_mail_smtp_rcpt(s, c);
                break;

            case NGX_SMTP_RSET:
                rc = ngx_mail_smtp_rset(s, c);
                break;

            case NGX_SMTP_NOOP:
                break;

            case NGX_SMTP_STARTTLS:
                rc = ngx_mail_smtp_starttls(s, c);
                ngx_str_set(&s->out, smtp_starttls);
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_smtp_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c, 0);

            ngx_str_set(&s->out, smtp_password);
            s->mail_state = ngx_smtp_auth_login_password;
            break;

        case ngx_smtp_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_smtp_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_smtp_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;
        }
    }

    if (s->buffer->pos < s->buffer->last) {
        s->blocked = 1;
    }

    switch (rc) {

    case NGX_DONE:
        ngx_mail_auth(s, c);
        return;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = ngx_smtp_start;
        s->state = 0;
        ngx_str_set(&s->out, smtp_invalid_command);

        /* fall through */

    case NGX_OK:
        s->args.nelts = 0;

        if (s->buffer->pos == s->buffer->last) {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
        }

        if (s->state) {
            s->arg_start = s->buffer->pos;
        }

        ngx_mail_send(c->write);
    }
}


static ngx_int_t
ngx_mail_smtp_helo(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg;
    ngx_mail_smtp_srv_conf_t  *sscf;

    if (s->args.nelts != 1) {
        ngx_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return NGX_OK;
    }

    arg = s->args.elts;

    s->smtp_helo.len = arg[0].len;

    s->smtp_helo.data = ngx_pnalloc(c->pool, arg[0].len);
    if (s->smtp_helo.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

    ngx_str_null(&s->smtp_from);
    ngx_str_null(&s->smtp_to);

    sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);

    if (s->command == NGX_SMTP_HELO) {
        s->out = sscf->server_name;

    } else {
        s->esmtp = 1;

#if (NGX_MAIL_SSL)

        if (c->ssl == NULL) {
            ngx_mail_ssl_conf_t  *sslcf;

            sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

            if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
                s->out = sscf->starttls_capability;
                return NGX_OK;
            }

            if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                s->out = sscf->starttls_only_capability;
                return NGX_OK;
            }
        }
#endif

        s->out = sscf->capability;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_mail_smtp_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_smtp_srv_conf_t  *sscf;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts == 0) {
        ngx_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return NGX_OK;
    }

    rc = ngx_mail_auth_parse(s, c);

    switch (rc) {

    case NGX_MAIL_AUTH_LOGIN:

        ngx_str_set(&s->out, smtp_username);
        s->mail_state = ngx_smtp_auth_login_username;

        return NGX_OK;

    case NGX_MAIL_AUTH_LOGIN_USERNAME:

        ngx_str_set(&s->out, smtp_password);
        s->mail_state = ngx_smtp_auth_login_password;

        return ngx_mail_auth_login_username(s, c, 1);

    case NGX_MAIL_AUTH_PLAIN:

        ngx_str_set(&s->out, smtp_next);
        s->mail_state = ngx_smtp_auth_plain;

        return NGX_OK;

    case NGX_MAIL_AUTH_CRAM_MD5:

        sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);

        if (!(sscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ngx_mail_auth_cram_md5_salt(s, c, "334 ", 4) == NGX_OK) {
            s->mail_state = ngx_smtp_auth_cram_md5;
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_mail_smtp_mail(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg, cmd;
    ngx_mail_smtp_srv_conf_t  *sscf;

    sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);

    if (!(sscf->auth_methods & NGX_MAIL_AUTH_NONE_ENABLED)) {
        ngx_mail_smtp_log_rejected_command(s, c, "client was rejected: \"%V\"");
        ngx_str_set(&s->out, smtp_auth_required);
        return NGX_OK;
    }

    /* auth none */

    if (s->smtp_from.len) {
        ngx_str_set(&s->out, smtp_bad_sequence);
        return NGX_OK;
    }

    if (s->args.nelts == 0) {
        ngx_str_set(&s->out, smtp_invalid_argument);
        return NGX_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_from.len = cmd.len;

    s->smtp_from.data = ngx_pnalloc(c->pool, cmd.len);
    if (s->smtp_from.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_from.data, cmd.data, cmd.len);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp mail from:\"%V\"", &s->smtp_from);

    ngx_str_set(&s->out, smtp_ok);

    return NGX_OK;
}


static ngx_int_t
ngx_mail_smtp_rcpt(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg, cmd;

    if (s->smtp_from.len == 0) {
        ngx_str_set(&s->out, smtp_bad_sequence);
        return NGX_OK;
    }

    if (s->args.nelts == 0) {
        ngx_str_set(&s->out, smtp_invalid_argument);
        return NGX_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_to.len = cmd.len;

    s->smtp_to.data = ngx_pnalloc(c->pool, cmd.len);
    if (s->smtp_to.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_to.data, cmd.data, cmd.len);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp rcpt to:\"%V\"", &s->smtp_to);

    s->auth_method = NGX_MAIL_AUTH_NONE;

    return NGX_DONE;
}


static ngx_int_t
ngx_mail_smtp_rset(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_null(&s->smtp_from);
    ngx_str_null(&s->smtp_to);
    ngx_str_set(&s->out, smtp_ok);

    return NGX_OK;
}


static ngx_int_t
ngx_mail_smtp_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
{
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
        if (sslcf->starttls) {

            /*
             * RFC3207 requires us to discard any knowledge
             * obtained from client before STARTTLS.
             */

            ngx_str_null(&s->smtp_helo);
            ngx_str_null(&s->smtp_from);
            ngx_str_null(&s->smtp_to);

            c->read->handler = ngx_mail_starttls_handler;
            return NGX_OK;
        }
    }

#endif

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


static ngx_int_t
ngx_mail_smtp_discard_command(ngx_mail_session_t *s, ngx_connection_t *c,
    char *err)
{
    ssize_t    n;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_mail_close_connection(c);
        return NGX_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ngx_mail_smtp_log_rejected_command(s, c, err);

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    return NGX_OK;
}


static void
ngx_mail_smtp_log_rejected_command(ngx_mail_session_t *s, ngx_connection_t *c,
    char *err)
{
    u_char      ch;
    ngx_str_t   cmd;
    ngx_uint_t  i;

    if (c->log->log_level < NGX_LOG_INFO) {
        return;
    }

    cmd.len = s->buffer->last - s->buffer->start;
    cmd.data = s->buffer->start;

    for (i = 0; i < cmd.len; i++) {
        ch = cmd.data[i];

        if (ch != CR && ch != LF) {
            continue;
        }

        cmd.data[i] = '_';
    }

    cmd.len = i;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, err, &cmd);
}
