
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_imap_module.h>


static ngx_int_t ngx_mail_imap_login(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_imap_authenticate(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_imap_capability(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_imap_starttls(ngx_mail_session_t *s,
    ngx_connection_t *c);


static u_char  imap_greeting[] = "* OK IMAP4 ready" CRLF;
static u_char  imap_star[] = "* ";
static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ OK" CRLF;
static u_char  imap_plain_next[] = "+ " CRLF;
static u_char  imap_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  imap_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  imap_bye[] = "* BYE" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;


void
ngx_mail_imap_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    s->out.len = sizeof(imap_greeting) - 1;
    s->out.data = imap_greeting;

    c->read->handler = ngx_mail_imap_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
        ngx_mail_close_connection(c);
    }

    ngx_mail_send(c->write);
}


void
ngx_mail_imap_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_imap_srv_conf_t  *iscf;

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
        if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
            == NGX_ERROR)
        {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

        s->buffer = ngx_create_temp_buf(c->pool, iscf->client_buffer_size);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = ngx_imap_start;
    c->read->handler = ngx_mail_imap_auth_state;

    ngx_mail_imap_auth_state(rev);
}


void
ngx_mail_imap_auth_state(ngx_event_t *rev)
{
    u_char              *p, *dst, *src, *end;
    ngx_str_t           *arg;
    ngx_int_t            rc;
    ngx_uint_t           tag, i;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    tag = 1;
    s->text.len = 0;
    s->out.len = sizeof(imap_ok) - 1;
    s->out.data = imap_ok;

    if (rc == NGX_OK) {

        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap auth command: %i",
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

        switch (s->mail_state) {

        case ngx_imap_start:

            switch (s->command) {

            case NGX_IMAP_LOGIN:
                rc = ngx_mail_imap_login(s, c);
                break;

            case NGX_IMAP_AUTHENTICATE:
                rc = ngx_mail_imap_authenticate(s, c);
                tag = (rc != NGX_OK);
                break;

            case NGX_IMAP_CAPABILITY:
                rc = ngx_mail_imap_capability(s, c);
                break;

            case NGX_IMAP_LOGOUT:
                s->quit = 1;
                s->text.len = sizeof(imap_bye) - 1;
                s->text.data = imap_bye;
                break;

            case NGX_IMAP_NOOP:
                break;

            case NGX_IMAP_STARTTLS:
                rc = ngx_mail_imap_starttls(s, c);
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_imap_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c);

            tag = 0;
            s->out.len = sizeof(imap_password) - 1;
            s->out.data = imap_password;
            s->mail_state = ngx_imap_auth_login_password;

            break;

        case ngx_imap_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_imap_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_imap_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;
        }

    } else if (rc == NGX_IMAP_NEXT) {
        tag = 0;
        s->out.len = sizeof(imap_next) - 1;
        s->out.data = imap_next;
    }

    switch (rc) {

    case NGX_DONE:
        ngx_mail_auth(s, c);
        return;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        s->state = 0;
        s->out.len = sizeof(imap_invalid_command) - 1;
        s->out.data = imap_invalid_command;
        s->mail_state = ngx_imap_start;
        break;
    }

    if (tag) {
        if (s->tag.len == 0) {
            s->tag.len = sizeof(imap_star) - 1;
            s->tag.data = (u_char *) imap_star;
        }

        if (s->tagged_line.len < s->tag.len + s->text.len + s->out.len) {
            s->tagged_line.len = s->tag.len + s->text.len + s->out.len;
            s->tagged_line.data = ngx_palloc(c->pool, s->tagged_line.len);
            if (s->tagged_line.data == NULL) {
                ngx_mail_close_connection(c);
                return;
            }
        }

        p = s->tagged_line.data;

        if (s->text.len) {
            p = ngx_cpymem(p, s->text.data, s->text.len);
        }

        p = ngx_cpymem(p, s->tag.data, s->tag.len);
        ngx_memcpy(p, s->out.data, s->out.len);

        s->out.len = s->text.len + s->tag.len + s->out.len;
        s->out.data = s->tagged_line.data;
    }

    if (rc != NGX_IMAP_NEXT) {
        s->args.nelts = 0;

        if (s->state) {
            /* preserve tag */
            s->arg_start = s->buffer->start + s->tag.len;
            s->buffer->pos = s->arg_start;
            s->buffer->last = s->arg_start;

        } else {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
            s->tag.len = 0;
        }
    }

    ngx_mail_send(c->write);
}


static ngx_int_t
ngx_mail_imap_login(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t            *arg;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    arg = s->args.elts;

    if (s->args.nelts != 2 || arg[0].len == 0) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = arg[0].len;
    s->login.data = ngx_palloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

    s->passwd.len = arg[1].len;
    s->passwd.data = ngx_palloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\" passwd:\"%V\"",
                   &s->login, &s->passwd);
#else
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\"", &s->login);
#endif

    return NGX_DONE;
}


static ngx_int_t
ngx_mail_imap_authenticate(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_imap_srv_conf_t  *iscf;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    rc = ngx_mail_auth_parse(s, c);

    switch (rc) {

    case NGX_MAIL_AUTH_LOGIN:

        s->out.len = sizeof(imap_username) - 1;
        s->out.data = imap_username;
        s->mail_state = ngx_imap_auth_login_username;

        return NGX_OK;

    case NGX_MAIL_AUTH_PLAIN:

        s->out.len = sizeof(imap_plain_next) - 1;
        s->out.data = imap_plain_next;
        s->mail_state = ngx_imap_auth_plain;

        return NGX_OK;

    case NGX_MAIL_AUTH_CRAM_MD5:

        iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ngx_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NGX_OK) {
            s->mail_state = ngx_imap_auth_cram_md5;
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_mail_imap_capability(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_imap_srv_conf_t  *iscf;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t       *sslcf;
#endif

    iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

#if (NGX_MAIL_SSL)

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
            s->text = iscf->starttls_capability;
            return NGX_OK;
        }

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
            s->text = iscf->starttls_only_capability;
            return NGX_OK;
        }
    }
#endif

    s->text = iscf->capability;

    return NGX_OK;
}


static ngx_int_t
ngx_mail_imap_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
{
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
        if (sslcf->starttls) {
            c->read->handler = ngx_mail_starttls_handler;
            return NGX_OK;
        }
    }

#endif

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}
