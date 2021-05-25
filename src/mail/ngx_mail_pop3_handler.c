
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_pop3_module.h>


static ngx_int_t ngx_mail_pop3_user(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_pass(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_capa(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_int_t stls);
static ngx_int_t ngx_mail_pop3_stls(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_apop(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_auth(ngx_mail_session_t *s, ngx_connection_t *c);


/*static u_char  pop3_greeting[] = "+OK POP3 ready" CRLF; zimbra uses the greeting specified by the directive */
static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_next[] = "+ " CRLF;
static u_char  pop3_gssapi_next[] = "+ " CRLF;
static u_char  pop3_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  pop3_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;
static u_char  pop3_unsupported_mech[] = "-ERR mechanism not supported" CRLF;
static u_char  pop3_nocleartext[] = "-ERR cleartext logins disabled" CRLF;
static u_char  pop3_authaborted[] = "-ERR authentication aborted" CRLF;
static u_char  pop3_login_failed[] = "-ERR invalid username/password" CRLF;
static u_char  pop3_auth_failed[] = "-ERR line is too long" CRLF;


void
ngx_mail_pop3_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char                    *p;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_pop3_srv_conf_t  *pscf;

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (pscf->auth_methods
        & (NGX_MAIL_AUTH_APOP_ENABLED|NGX_MAIL_AUTH_CRAM_MD5_ENABLED))
    {
        if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        s->out.data = ngx_pnalloc(c->pool, pscf->greeting.len + s->salt.len - 1);
        if (s->out.data == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(s->out.data, pscf->greeting.data, pscf->greeting.len - 2);
        *p++ = ' ';
        p = ngx_cpymem(p, s->salt.data, s->salt.len);

        s->out.len = p - s->out.data;

    } else {
        s->out = pscf->greeting;
    }

    c->read->handler = ngx_mail_pop3_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_mail_close_connection(c);
    }

    ngx_mail_send(c->write);
}


void
ngx_mail_pop3_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;
    ngx_mail_pop3_srv_conf_t  *pscf;

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

        pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

        s->buffer = ngx_create_temp_buf(c->pool, pscf->client_buffer_size);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    ngx_mail_set_pop3_parse_state_start(s);
    s->mail_state = ngx_pop3_start;
    c->read->handler = ngx_mail_pop3_auth_state;

    ngx_mail_pop3_auth_state(rev);
}


void
ngx_mail_pop3_auth_state(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "pop3 send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    ngx_str_set(&s->out, pop3_ok);

    if (rc == NGX_OK) {
        switch (s->mail_state) {

        case ngx_pop3_start:

            switch (s->command) {

            case NGX_POP3_USER:
                rc = ngx_mail_pop3_user(s, c);
                s->mail_state = ngx_pop3_user;
                break;

            case NGX_POP3_CAPA:
                rc = ngx_mail_pop3_capa(s, c, 1);
                break;

            case NGX_POP3_APOP:
                rc = ngx_mail_pop3_apop(s, c);
                break;

            case NGX_POP3_AUTH:
                rc = ngx_mail_pop3_auth(s, c);
                break;

            case NGX_POP3_QUIT:
                s->quit = 1;
                break;

            case NGX_POP3_NOOP:
                break;

            case NGX_POP3_STLS:
                rc = ngx_mail_pop3_stls(s, c);
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_pop3_user:

            switch (s->command) {

            case NGX_POP3_PASS:
                rc = ngx_mail_pop3_pass(s, c);
                s->mail_state = ngx_pop3_user;
                break;

            case NGX_POP3_CAPA:
                rc = ngx_mail_pop3_capa(s, c, 0);
                break;

            case NGX_POP3_QUIT:
                s->quit = 1;
                break;

            case NGX_POP3_NOOP:
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        /* suppress warnings */
        case ngx_pop3_passwd:
            break;

        case ngx_pop3_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c, 0);

            if(rc == NGX_MAIL_AUTH_ARGUMENT) {
                ngx_str_set(&s->out, pop3_password);
                s->mail_state = ngx_pop3_auth_login_password;
            }
            break;

        case ngx_pop3_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_pop3_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_pop3_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;

        case ngx_pop3_auth_gssapi:
            {
                ngx_str_t output;
                ngx_str_set(&output, "");
                rc = ngx_mail_auth_gssapi(s, c, &output);
                if (rc == NGX_MAIL_AUTH_ARGUMENT) {
                    s->mail_state = ngx_pop3_auth_gssapi;
                    s->out = output;
                }
                break;
            }

        case ngx_pop3_auth_external:
            rc = ngx_mail_auth_external(s, c, 0);
            break;
        }
    }

    switch (rc) {

    case NGX_DONE:
        ngx_mail_do_auth(s, c);
        return;

    case NGX_OK:
        s->arg_start = NULL;
        ngx_mail_set_pop3_parse_state_start(s);
        break;

    case NGX_MAIL_AUTH_ABORT:
        ngx_str_set(&s->out, pop3_authaborted);
        s->mail_state = ngx_pop3_start;
        s->arg_start = NULL;
        ngx_mail_set_pop3_parse_state_start(s);
        break;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_LOGIN_FAILED:
        ngx_str_set(&s->out, pop3_login_failed);
        s->mail_state = ngx_pop3_start;
        s->arg_start = NULL;
        ngx_mail_set_pop3_parse_state_start(s);
        break;

    case NGX_MAIL_AUTH_FAILED:
        ngx_str_set(&s->out, pop3_auth_failed);
        s->mail_state = ngx_pop3_start;
        s->arg_start = NULL;
        ngx_mail_set_pop3_parse_state_start(s);
        break;

    case NGX_MAIL_PARSE_INVALID_AUTH_MECH:
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "unsupported POP auth mechanism");
        ngx_str_set(&s->out, pop3_unsupported_mech);
        s->mail_state = ngx_pop3_start;
        s->arg_start = NULL;
        ngx_mail_set_pop3_parse_state_start(s);
        break;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        ngx_str_set(&s->out, pop3_invalid_command);
        s->mail_state = ngx_pop3_start;
        s->arg_start = NULL;
        ngx_mail_set_pop3_parse_state_start(s);
        break;

    case NGX_MAIL_AUTH_ARGUMENT:
        s->arg_start = s->buffer->start;
        ngx_mail_set_pop3_parse_state_argument(s);
        break;
    }

    s->args.nelts = 0;
    ngx_mail_reset_parse_buffer(s);

    ngx_mail_send(c->write);
}

static ngx_int_t
ngx_mail_pop3_user(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        ngx_str_set(&s->out, pop3_nocleartext);
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 1) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    if(arg[0].len > NGX_MAIL_MAX_LOGIN_LEN) {
        ngx_str_null(&s->login);
        return NGX_OK;
    }
    s->login.len = arg[0].len;
    s->login.data = ngx_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 login: \"%V\"", &s->login);

    return NGX_OK;
}


static ngx_int_t
ngx_mail_pop3_pass(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg;

    if (s->args.nelts != 1) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

    if (s->login.len == 0 || arg[0].len > NGX_MAIL_MAX_PASSWORD_LEN) {
        return NGX_MAIL_LOGIN_FAILED;
    }

    s->passwd.len = arg[0].len;
    s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->passwd.data, arg[0].data, s->passwd.len);

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 passwd: \"%V\"", &s->passwd);
#endif

     s->auth_method = NGX_MAIL_AUTH_PASSWD;
     s->usedauth = 0;

    return NGX_DONE;
}


static ngx_int_t
ngx_mail_pop3_capa(ngx_mail_session_t *s, ngx_connection_t *c, ngx_int_t stls)
{
    ngx_mail_pop3_srv_conf_t  *pscf;

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

#if (NGX_MAIL_SSL)

    if (stls && c->ssl == NULL) {
        ngx_mail_ssl_conf_t  *sslcf;

        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
            s->out = pscf->starttls_capability;
            return NGX_OK;
        }

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
            s->out = pscf->starttls_only_capability;
            return NGX_OK;
        }
    }

#endif

    s->out = pscf->capability;
    return NGX_OK;
}


static ngx_int_t
ngx_mail_pop3_stls(ngx_mail_session_t *s, ngx_connection_t *c)
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


static ngx_int_t
ngx_mail_pop3_apop(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg;
    ngx_mail_pop3_srv_conf_t  *pscf;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 2) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

    if (!(pscf->auth_methods & NGX_MAIL_AUTH_APOP_ENABLED)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

    s->login.len = arg[0].len;
    s->login.data = ngx_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

    s->passwd.len = arg[1].len;
    s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 apop: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = NGX_MAIL_AUTH_APOP;
    s->usedauth = 0;

    return NGX_DONE;
}


static ngx_int_t
ngx_mail_pop3_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_mail_pop3_srv_conf_t  *pscf;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

    if (s->args.nelts == 0) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    rc = ngx_mail_auth_parse(s, c);

    switch (rc) {

    case NGX_MAIL_AUTH_LOGIN:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_LOGIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, pop3_username);
        s->mail_state = ngx_pop3_auth_login_username;

        return NGX_MAIL_AUTH_ARGUMENT;

    case NGX_MAIL_AUTH_LOGIN_USERNAME:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_LOGIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, pop3_password);
        s->mail_state = ngx_pop3_auth_login_password;

        return ngx_mail_auth_login_username(s, c, 0);

    case NGX_MAIL_AUTH_PLAIN:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, pop3_next);
        s->mail_state = ngx_pop3_auth_plain;

        return NGX_MAIL_AUTH_ARGUMENT;

    case NGX_MAIL_AUTH_PLAIN_IR:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        return ngx_mail_auth_plain(s, c, 1);

    case NGX_MAIL_AUTH_GSSAPI:
        if( !(pscf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, pop3_gssapi_next);
        s->mail_state = ngx_pop3_auth_gssapi;
        return NGX_MAIL_AUTH_ARGUMENT;

    case NGX_MAIL_AUTH_GSSAPI_IR:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        s->mail_state = ngx_pop3_auth_gssapi;
        ngx_str_t output;
        ngx_str_set(&output, "");
        int res = ngx_mail_auth_gssapi(s, c, &output);
        if(res == NGX_MAIL_AUTH_ARGUMENT) {
            s->out = output;
            return NGX_MAIL_AUTH_ARGUMENT;
        } else {
            return res;
        }

    case NGX_MAIL_AUTH_CRAM_MD5:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }

        if (ngx_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NGX_OK) {
            s->mail_state = ngx_pop3_auth_cram_md5;
            return NGX_MAIL_AUTH_ARGUMENT;
        }

        return NGX_ERROR;

    case NGX_MAIL_AUTH_EXTERNAL:

        if (!(pscf->auth_methods & NGX_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        ngx_str_set(&s->out, pop3_username);
        s->mail_state = ngx_pop3_auth_external;

        return NGX_OK;

    default:
        break;
    }

    return rc;
}
