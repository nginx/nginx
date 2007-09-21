
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>


static void ngx_mail_init_session(ngx_connection_t *c);

#if (NGX_MAIL_SSL)
static void ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_mail_ssl_handshake_handler(ngx_connection_t *c);
#endif


void
ngx_mail_init_connection(ngx_connection_t *c)
{
    in_addr_t             in_addr;
    socklen_t             len;
    ngx_uint_t            i;
    struct sockaddr_in    sin;
    ngx_mail_log_ctx_t   *ctx;
    ngx_mail_in_port_t   *imip;
    ngx_mail_in_addr_t   *imia;
    ngx_mail_session_t   *s;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;
#endif


    /* find the server configuration for the address:port */

    /* AF_INET only */

    imip = c->listening->servers;
    imia = imip->addrs;

    i = 0;

    if (imip->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

#if (NGX_WIN32)
        if (c->local_sockaddr) {
            in_addr =
                   ((struct sockaddr_in *) c->local_sockaddr)->sin_addr.s_addr;

        } else
#endif
        {
            len = sizeof(struct sockaddr_in);
            if (getsockname(c->fd, (struct sockaddr *) &sin, &len) == -1) {
                ngx_connection_error(c, ngx_socket_errno,
                                     "getsockname() failed");
                ngx_mail_close_connection(c);
                return;
            }

            in_addr = sin.sin_addr.s_addr;
        }

        /* the last address is "*" */

        for ( /* void */ ; i < imip->naddrs - 1; i++) {
            if (in_addr == imia[i].addr) {
                break;
            }
        }
    }


    s = ngx_pcalloc(c->pool, sizeof(ngx_mail_session_t));
    if (s == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    s->main_conf = imia[i].ctx->main_conf;
    s->srv_conf = imia[i].ctx->srv_conf;

    s->addr_text = &imia[i].addr_text;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_mail_log_ctx_t));
    if (ctx == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_mail_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = NGX_ERROR_INFO;

#if (NGX_MAIL_SSL)

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (sslcf->enable) {
        ngx_mail_ssl_init_connection(&sslcf->ssl, c);
        return;
    }

#endif

    ngx_mail_init_session(c);
}


#if (NGX_MAIL_SSL)

void
ngx_mail_starttls_handler(ngx_event_t *rev)
{
    ngx_connection_t     *c;
    ngx_mail_session_t   *s;
    ngx_mail_ssl_conf_t  *sslcf;

    c = rev->data;
    s = c->data;
    s->starttls = 1;

    c->log->action = "in starttls state";

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    ngx_mail_ssl_init_connection(&sslcf->ssl, c);
}


static void
ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c)
{
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    if (ngx_ssl_create_connection(ssl, c, 0) == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {

        s = c->data;

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        ngx_add_timer(c->read, cscf->timeout);

        c->ssl->handler = ngx_mail_ssl_handshake_handler;

        return;
    }

    ngx_mail_ssl_handshake_handler(c);
}


static void
ngx_mail_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    if (c->ssl->handshaked) {

        s = c->data;

        if (s->starttls) {
            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            c->read->handler = cscf->protocol->init_protocol;
            c->write->handler = ngx_mail_send;

            cscf->protocol->init_protocol(c->read);

            return;
        }

        ngx_mail_init_session(c);
        return;
    }

    ngx_mail_close_connection(c);
}

#endif


static void
ngx_mail_init_session(ngx_connection_t *c)
{
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    s = c->data;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    s->protocol = cscf->protocol->type;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_mail_max_module);
    if (s->ctx == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    c->write->handler = ngx_mail_send;

    cscf->protocol->init_session(s, c);
}


ngx_int_t
ngx_mail_salt(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_mail_core_srv_conf_t *cscf)
{
    s->salt.data = ngx_palloc(c->pool,
                              sizeof(" <18446744073709551616.@>" CRLF) - 1
                              + NGX_TIME_T_LEN
                              + cscf->server_name.len);
    if (s->salt.data == NULL) {
        return NGX_ERROR;
    }

    s->salt.len = ngx_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
                              ngx_random(), ngx_time(), &cscf->server_name)
                  - s->salt.data;

    return NGX_OK;
}


#if (NGX_MAIL_SSL)

ngx_int_t
ngx_mail_starttls_only(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl) {
        return 0;
    }

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
        return 1;
    }

    return 0;
}

#endif


ngx_int_t
ngx_mail_auth_plain(ngx_mail_session_t *s, ngx_connection_t *c, ngx_uint_t n)
{
    u_char     *p, *last;
    ngx_str_t  *arg, plain;

    arg = s->args.elts;

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\"", &arg[n]);
#endif

    plain.data = ngx_palloc(c->pool, ngx_base64_decoded_length(arg[n].len));
    if (plain.data == NULL){
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&plain, &arg[n]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    p = plain.data;
    last = p + plain.len;

    while (p < last && *p++) { /* void */ }

    if (p == last) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid login in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.data = p;

    while (p < last && *p) { p++; }

    if (p == last) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid password in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = p++ - s->login.data;

    s->passwd.len = last - p;
    s->passwd.data = p;

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
#endif

    return NGX_DONE;
}


ngx_int_t
ngx_mail_auth_login_username(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg;

    arg = s->args.elts;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &arg[0]);

    s->login.data = ngx_palloc(c->pool, ngx_base64_decoded_length(arg[0].len));
    if (s->login.data == NULL){
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &s->login);

    return NGX_OK;
}


ngx_int_t
ngx_mail_auth_login_password(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg;

    arg = s->args.elts;

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &arg[0]);
#endif

    s->passwd.data = ngx_palloc(c->pool, ngx_base64_decoded_length(arg[0].len));
    if (s->passwd.data == NULL){
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&s->passwd, &arg[0]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &s->passwd);
#endif

    return NGX_DONE;
}


ngx_int_t
ngx_mail_auth_cram_md5_salt(ngx_mail_session_t *s, ngx_connection_t *c,
    char *prefix, size_t len)
{
    u_char      *p;
    ngx_str_t    salt;
    ngx_uint_t   n;

    p = ngx_palloc(c->pool, len + ngx_base64_encoded_length(s->salt.len) + 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    salt.data = ngx_cpymem(p, prefix, len);
    s->salt.len -= 2;

    ngx_encode_base64(&salt, &s->salt);

    s->salt.len += 2;
    n = len + salt.len;
    p[n++] = CR; p[n++] = LF;

    s->out.len = n;
    s->out.data = p;

    return NGX_OK;
}


ngx_int_t
ngx_mail_auth_cram_md5(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char     *p, *last;
    ngx_str_t  *arg;

    arg = s->args.elts;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\"", &arg[0]);

    s->login.data = ngx_palloc(c->pool, ngx_base64_decoded_length(arg[0].len));
    if (s->login.data == NULL){
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH CRAM-MD5 command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    p = s->login.data;
    last = p + s->login.len;

    while (p < last) {
        if (*p++ == ' ') {
            s->login.len = p - s->login.data - 1;
            s->passwd.len = last - p;
            s->passwd.data = p;
            break;
        }
    }

    if (s->passwd.len != 32) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid CRAM-MD5 hash in AUTH CRAM-MD5 command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = NGX_MAIL_AUTH_CRAM_MD5;

    return NGX_DONE;
}


void
ngx_mail_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len == 0) {
        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            ngx_mail_close_connection(c);
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
            ngx_mail_close_connection(c);
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return;
    }

    /* n == NGX_AGAIN */

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return;
    }
}


ngx_int_t
ngx_mail_read_command(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_str_t                  l;
    ngx_mail_core_srv_conf_t  *cscf;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_mail_close_connection(c);
        return NGX_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    rc = cscf->protocol->parse_command(s);

    if (rc == NGX_AGAIN) {

        if (s->buffer->last < s->buffer->end) {
            return rc;
        }

        l.len = s->buffer->last - s->buffer->start;
        l.data = s->buffer->start;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent too long command \"%V\"", &l);

        s->quit = 1;

        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (rc == NGX_IMAP_NEXT || rc == NGX_MAIL_PARSE_INVALID_COMMAND) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_mail_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;
    s->state = 0;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    s->login_attempt++;

    ngx_mail_auth_http_init(s);
}


void
ngx_mail_session_internal_server_error(ngx_mail_session_t *s)
{
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    s->out = cscf->protocol->internal_server_error;
    s->quit = 1;

    ngx_mail_send(s->connection->write);
}


void
ngx_mail_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "close mail connection: %d", c->fd);

#if (NGX_MAIL_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_mail_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


u_char *
ngx_mail_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_mail_session_t  *s;
    ngx_mail_log_ctx_t  *ctx;

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

    p = ngx_snprintf(buf, len, "%s, server: %V",
                     s->starttls ? " using starttls" : "",
                     s->addr_text);
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

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}
