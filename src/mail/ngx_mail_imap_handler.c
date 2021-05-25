
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
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
static ngx_int_t ngx_mail_imap_id(ngx_mail_session_t *s,
    ngx_connection_t *c);

static u_char  imap_star[] = "*";
static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ " CRLF;
static u_char  imap_plain_next[] = "+ " CRLF;
static u_char  imap_gssapi_next[] = "+ " CRLF;
static u_char  imap_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  imap_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;
static u_char  imap_unsupported_mech[] = "NO mechanism not supported" CRLF;
static u_char  imap_nocleartext[] = "NO cleartext logins disabled" CRLF;
static u_char  imap_authaborted[] = "BAD AUTHENTICATE aborted" CRLF;
static u_char  imap_login_failed[] = "NO LOGIN failed" CRLF;
static u_char  imap_authenticate_failed[] = "NO AUTHENTICATE failed" CRLF;


void
ngx_mail_imap_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_imap_srv_conf_t  *iscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

    s->out = iscf->greeting;

    c->read->handler = ngx_mail_imap_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
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

    ngx_mail_set_imap_parse_state_start(s);
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
        ngx_mail_end_session(s);    /* send IMAP BYE on timeout */
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
    ngx_str_set(&s->out, imap_ok);
    s->text.len = 0;

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
                break;

            case NGX_IMAP_CAPABILITY:
                rc = ngx_mail_imap_capability(s, c);
                break;

            case NGX_IMAP_LOGOUT:
                s->quit = 1;
                break;

            case NGX_IMAP_NOOP:
                break;

            case NGX_IMAP_STARTTLS:
                rc = ngx_mail_imap_starttls(s, c);
                break;

            case NGX_IMAP_ID:
                rc = ngx_mail_imap_id(s, c);
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_imap_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c, 0);

            if (rc == NGX_MAIL_AUTH_ARGUMENT) {
                ngx_str_set(&s->out, imap_password);
                s->mail_state = ngx_imap_auth_login_password;
            }
            break;

        case ngx_imap_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_imap_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_imap_auth_gssapi:
        {
            ngx_str_t output;
            ngx_str_set(&output, "");
            rc = ngx_mail_auth_gssapi(s, c, &output);
            if (rc == NGX_MAIL_AUTH_ARGUMENT) {
                s->mail_state = ngx_imap_auth_gssapi;
                s->out = output;
            }
            break;
        }

        case ngx_imap_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;

        case ngx_imap_auth_external:
            rc = ngx_mail_auth_external(s, c, 0);
            break;
        }

    } else if (rc == NGX_IMAP_NEXT) {
        tag = 0;
        ngx_str_set(&s->out, imap_next);
    }

    switch (rc) {

    case NGX_DONE:
        ngx_mail_do_auth(s, c);
        return;

    case NGX_OK:
        ngx_mail_set_imap_parse_state_start(s);
        s->arg_start = NULL;
        ngx_mail_reset_parse_buffer(s);
        break;

    case NGX_MAIL_AUTH_ABORT:
        ngx_str_set(&s->out, imap_authaborted);
        s->mail_state = ngx_imap_start;
        ngx_mail_set_imap_parse_state_start(s);
        s->arg_start = NULL;
        ngx_mail_reset_parse_buffer(s);
        break;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_AUTH_FAILED:
        ngx_str_set(&s->out, imap_authenticate_failed);
        s->mail_state = ngx_imap_start;
        ngx_mail_set_imap_parse_state_start(s);
        s->arg_start = NULL;
        ngx_mail_reset_parse_buffer(s);
        break;

    case NGX_MAIL_LOGIN_FAILED:
        ngx_str_set(&s->out, imap_login_failed);
        s->mail_state = ngx_imap_start;
        ngx_mail_set_imap_parse_state_start(s);
        s->arg_start = NULL;
        ngx_mail_reset_parse_buffer(s);
        break;

    case NGX_MAIL_PARSE_INVALID_AUTH_MECH:
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "unsupported IMAP auth mechanism");
        ngx_str_set(&s->out, imap_unsupported_mech);
        s->mail_state = ngx_imap_start;
        ngx_mail_set_imap_parse_state_start(s);
        s->arg_start = NULL;
        ngx_mail_reset_parse_buffer(s);
        break;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        ngx_str_set(&s->out, imap_invalid_command);
        s->mail_state = ngx_imap_start;
        ngx_mail_set_imap_parse_state_start(s);
        s->arg_start = NULL;
        ngx_mail_reset_parse_buffer(s);
        break;

    case NGX_MAIL_AUTH_ARGUMENT:
        ngx_mail_set_imap_parse_state_argument(s);
        /* preserve tag, since tag's memory is allocated in buffer, need to set the
         * buffer pos after tag */
        s->arg_start = s->buffer->start + s->tag.len;
        s->buffer->pos = s->arg_start;
        s->buffer->last = s->arg_start;
        tag = 0; // just output s->out
        break;

    case NGX_IMAP_NEXT:
        /* do nothing, preserve all the state, including s->state, s->mail_state,
         * , s->buffer, s->arg_start
         */
        break;
    }

    if (tag) {
        if (s->tag.len == 0) {
            ngx_str_set(&s->tag, imap_star);
        }

        if (s->tagged_line.len < s->tag.len + s->text.len + s->out.len + 1) {
            s->tagged_line.len = s->tag.len + s->text.len + s->out.len + 1;
            s->tagged_line.data = ngx_pnalloc(c->pool, s->tagged_line.len);
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
       *p++ = ' '; /* the space between tag and out */
        ngx_memcpy(p, s->out.data, s->out.len);

        s->out.len = s->text.len + s->tag.len + 1 /*for space*/ + s->out.len;
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
    ngx_str_t  *arg;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        ngx_str_set(&s->text, imap_nocleartext);
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    arg = s->args.elts;

    if (s->args.nelts != 2 || arg[0].len == 0) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (arg[0].len > NGX_MAIL_MAX_LOGIN_LEN) {
        return NGX_MAIL_LOGIN_FAILED;
    }

    s->login.len = arg[0].len;
    s->login.data = ngx_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

    if (arg[1].len > NGX_MAIL_MAX_PASSWORD_LEN) {
        return NGX_MAIL_LOGIN_FAILED;
    }

    s->passwd.len = arg[1].len;
    s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
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

    s->auth_method = NGX_MAIL_AUTH_PASSWD;
    s->usedauth = 0;
    return NGX_DONE;
}


static ngx_int_t
ngx_mail_imap_authenticate(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc, res;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_imap_srv_conf_t  *iscf;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    rc = ngx_mail_auth_parse(s, c);

    iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

    switch (rc) {

    case NGX_MAIL_AUTH_LOGIN:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_LOGIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, imap_username);
        s->mail_state = ngx_imap_auth_login_username;

        return NGX_MAIL_AUTH_ARGUMENT;

    case NGX_MAIL_AUTH_LOGIN_USERNAME:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_LOGIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }

        res = ngx_mail_auth_login_username(s, c, 1);
        if (res == NGX_MAIL_AUTH_ARGUMENT) {
            ngx_str_set(&s->out, imap_password);
            s->mail_state = ngx_imap_auth_login_password;
            return NGX_MAIL_AUTH_ARGUMENT;
        } else {
            return res;
        }


    case NGX_MAIL_AUTH_PLAIN:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, imap_plain_next);
        s->mail_state = ngx_imap_auth_plain;

        return NGX_MAIL_AUTH_ARGUMENT;

    case NGX_MAIL_AUTH_PLAIN_IR:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        return ngx_mail_auth_plain(s, c, 1);

    case NGX_MAIL_AUTH_GSSAPI:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        ngx_str_set(&s->out, imap_gssapi_next);
        s->mail_state = ngx_imap_auth_gssapi;

        return NGX_MAIL_AUTH_ARGUMENT;

    case NGX_MAIL_AUTH_GSSAPI_IR:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }
        s->mail_state = ngx_imap_auth_gssapi;
        ngx_str_t output;
        ngx_str_set(&output, "");
        res = ngx_mail_auth_gssapi(s, c, &output);
        if(res == NGX_MAIL_AUTH_ARGUMENT) {
            s->out = output;
            return NGX_MAIL_AUTH_ARGUMENT;
        } else {
            return res;
        }

    case NGX_MAIL_AUTH_CRAM_MD5:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
        }

        if (s->salt.data == NULL) {
            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ngx_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NGX_OK) {
            s->mail_state = ngx_imap_auth_cram_md5;
            return NGX_MAIL_AUTH_ARGUMENT;
        }

        return NGX_ERROR;

    case NGX_MAIL_AUTH_EXTERNAL:

        if (!(iscf->auth_methods & NGX_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        ngx_str_set(&s->out, imap_username);
        s->mail_state = ngx_imap_auth_external;

        return NGX_OK;
    }

    return rc;
}


static ngx_int_t
ngx_mail_imap_capability(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_imap_srv_conf_t  *iscf;

    iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

#if (NGX_MAIL_SSL)

    if (c->ssl == NULL) {
        ngx_mail_ssl_conf_t  *sslcf;

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


static ngx_int_t
ngx_mail_imap_id(ngx_mail_session_t *s, ngx_connection_t * c)
{
    size_t i;
    ngx_mail_imap_srv_conf_t  *iscf;
    ngx_str_t                 *key, * value;

    iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);
    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,s->connection->log,0,
      "imap id received %d parameters from client", s->args.nelts);
    if (s->args.nelts) {
      ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
          "client ID params [%d pair(s)]",
          s->args.nelts/2);
        for (i = 0; i < s->args.nelts / 2; ++i) {
            ngx_log_debug3 (NGX_LOG_DEBUG_MAIL,
                  s->connection->log, 0,
                  "[pair %d] field:'%V' value:'%V'",
                  i+1,
                  (ngx_str_t*)s->args.elts + 2 * i,
                  (ngx_str_t*)s->args.elts + 2 * i + 1
                );
            key = (ngx_str_t*)s->args.elts + 2 * i;
            /* bug 64978, add support to "name" and "version" field */
            if (key->len == sizeof ("name") - 1 &&
                (key->data[0] == 'N' || key->data[0] == 'n') &&
                (key->data[1] == 'A' || key->data[1] == 'a') &&
                (key->data[2] == 'M' || key->data[2] == 'm') &&
                (key->data[3] == 'E' || key->data[3] == 'e')) {
                value = (ngx_str_t*)s->args.elts + 2 * i + 1;

                s->id_name.data = ngx_pnalloc(c->pool, value->len);
                if (s->id_name.data == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(s->id_name.data, value->data, value->len);
                s->id_name.len = value->len;
            } else if (key->len == sizeof ("version") - 1 &&
                    (key->data[0] == 'V' || key->data[0] == 'v') &&
                    (key->data[1] == 'E' || key->data[1] == 'e') &&
                    (key->data[2] == 'R' || key->data[2] == 'r') &&
                    (key->data[3] == 'S' || key->data[3] == 's') &&
                    (key->data[4] == 'I' || key->data[4] == 'i') &&
                    (key->data[5] == 'O' || key->data[5] == 'o') &&
                    (key->data[6] == 'N' || key->data[6] == 'n')) {
                value = (ngx_str_t*)s->args.elts + 2 * i + 1;

                s->id_version.data = ngx_pnalloc(c->pool, value->len);
                if (s->id_version.data == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(s->id_version.data, value->data, value->len);
                s->id_version.len = value->len;
            }
        }
    }
    s->text = iscf->id;

    return NGX_OK;
}
