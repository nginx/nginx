
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <ngx_mail_throttle_module.h>
#include <ngx_mail_pop3_module.h>
#include <ngx_mail_smtp_module.h>
#include <ngx_mail_zmauth_module.h>

static void ngx_mail_init_session(ngx_connection_t *c);
static void ngx_mail_choke_session(throttle_callback_t *cb);
static void ngx_mail_allow_session(throttle_callback_t *cb);
static void ngx_mail_allow_userauth(throttle_callback_t *cb);
static void ngx_mail_choke_userauth(throttle_callback_t *cb);

#if (NGX_MAIL_SSL)
static void ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_mail_ssl_handshake_handler(ngx_connection_t *c);
static ngx_int_t ngx_mail_verify_cert(ngx_mail_session_t *s,
    ngx_connection_t *c);
#endif

static int ngx_mail_create_sasl_context(ngx_connection_t *s);
static void ngx_mail_dispose_sasl_context(ngx_mail_session_t *s);
static int ngx_mail_initialize_sasl(ngx_connection_t *c);
static int ngx_mail_sasl_startstep(ngx_connection_t *c, const char *mech,
    ngx_str_t  *response, ngx_str_t  *challenge);
static int ngx_mail_sasl_log(void *context, int level, const char * message);
static int ngx_mail_sasl_pauthorize(sasl_conn_t *conn, void *context,
    const char *authz, unsigned authzlen, const char *authc, unsigned authclen,
    const char *realm, unsigned rlen, struct propctx *propctx);

static ngx_str_t    krb5_cooked_password = ngx_string("KKK");

static ngx_flag_t sasl_initialized = 0;

void
ngx_mail_init_connection(ngx_connection_t *c)
{
    ngx_uint_t                 i;
    ngx_uint_t                 remote_port=0;
    ngx_mail_port_t           *port;
    struct sockaddr           *sa;
    struct sockaddr_in        *sin;
    ngx_mail_log_ctx_t        *ctx;
    ngx_mail_in_addr_t        *addr;
    ngx_mail_session_t        *s;
    ngx_mail_addr_conf_t      *addr_conf;
    ngx_mail_core_srv_conf_t  *cscf;
    //u_char                     text[NGX_SOCKADDR_STRLEN];
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    ngx_mail_in6_addr_t       *addr6;
#endif


    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_mail_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_mail_session_t));
    if (s == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    s->signature = NGX_MAIL_MODULE;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_set_connection_log(c, cscf->error_log);

    //len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);

    switch (c->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->sockaddr;
            remote_port = ntohs(sin6->sin6_port);
            break;
#endif
        default:
            sin = (struct sockaddr_in *) c->sockaddr;
            remote_port = ntohs(sin->sin_port);
            break;
    }

    if (remote_port && remote_port < 65536) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V:%ui connected to %V",
                c->number, &c->addr_text, remote_port, s->addr_text);
    } else {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                c->number, &c->addr_text, s->addr_text);
    }

    ctx = ngx_palloc(c->pool, sizeof(ngx_mail_log_ctx_t));
    if (ctx == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->client_port = remote_port;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_mail_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = NGX_ERROR_INFO;

#if (NGX_MAIL_SSL)
    {
    ngx_mail_ssl_conf_t  *sslcf;

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (sslcf->enable || addr_conf->ssl) {
        c->log->action = "SSL handshaking";

        ngx_mail_ssl_init_connection(&sslcf->ssl, c);
        return;
    }

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

    if (ngx_ssl_create_connection(ssl, c, 0) != NGX_OK) {
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

        if (ngx_mail_verify_cert(s, c) != NGX_OK) {
            return;
        }

        if (s->starttls) {
            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            c->read->handler = cscf->protocol->init_protocol;
            c->write->handler = ngx_mail_send;

            cscf->protocol->init_protocol(c->read);

            return;
        }

        c->read->ready = 0;

        ngx_mail_init_session(c);
        return;
    }

    ngx_mail_close_connection(c);
}


static ngx_int_t
ngx_mail_verify_cert(ngx_mail_session_t *s, ngx_connection_t *c)
{
    long                       rc;
    X509                      *cert;
    ngx_mail_ssl_conf_t       *sslcf;
    ngx_mail_core_srv_conf_t  *cscf;

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (!sslcf->verify) {
        return NGX_OK;
    }

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc != X509_V_OK
        && (sslcf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client SSL certificate verify error: (%l:%s)",
                      rc, X509_verify_cert_error_string(rc));

        ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                      (SSL_get0_session(c->ssl->connection)));

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        s->out = cscf->protocol->cert_error;
        s->quit = 1;

        c->write->handler = ngx_mail_send;

        ngx_mail_send(s->connection->write);
        return NGX_ERROR;
    }

    if (sslcf->verify == 1) {
        cert = SSL_get_peer_certificate(c->ssl->connection);

        if (cert == NULL) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent no required SSL certificate");

            ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            s->out = cscf->protocol->no_cert;
            s->quit = 1;

            c->write->handler = ngx_mail_send;

            ngx_mail_send(s->connection->write);
            return NGX_ERROR;
        }

        X509_free(cert);
    }

    return NGX_OK;
}

#endif


static void
ngx_mail_init_session(ngx_connection_t *c)
{
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_throttle_srv_conf_t *tscf;
    throttle_callback_t          *cb;
    ngx_uint_t                    login_ip_max;

    s = c->data;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);

    s->protocol = cscf->protocol->type;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_mail_max_module);
    if (s->ctx == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->cleanup = NULL;

    /* throttle */
    cb = ngx_pcalloc(c->pool, sizeof(throttle_callback_t));
    if(cb == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ngx_memset(cb, 0, sizeof(throttle_callback_t));
    cb->session = s;
    cb->connection = c;
    cb->log = ngx_cycle->log;
    cb->pool = c->pool;
    cb->on_allow = ngx_mail_allow_session;
    cb->on_deny = ngx_mail_choke_session;

    login_ip_max = ngx_mail_throttle_ip_max_for_protocol(tscf, s->protocol);
    if (login_ip_max == 0) {
        cb->on_allow(cb); //unlimited, direct allow session
    } else {
        ngx_mail_throttle_whitelist_ip(c->addr_text, cb);
    }
}

static void
ngx_mail_choke_session(throttle_callback_t *cb)
{
    ngx_connection_t             *c;
    ngx_mail_session_t           *s;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_str_t                     bye, msg;
    u_char                       *p;

    c = (ngx_connection_t *)cb->connection;
    s = c->data;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    msg = tscf->mail_login_ip_rejectmsg;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log,0,
        "ip throttle:%V choking mail session", &c->addr_text);

    if(s->protocol == NGX_MAIL_IMAP_PROTOCOL) {
        bye.data = 
        ngx_palloc(c->pool, 
            sizeof("* BYE ")- 1 +
            msg.len +
            sizeof(CRLF) - 1
            );
        if (bye.data == NULL) {
            ngx_str_set(&bye, "* BYE" CRLF);
        } else {
            p = bye.data;
            p = ngx_cpymem(p, "* BYE ", sizeof("* BYE ") - 1);
            p = ngx_cpymem(p, msg.data, msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p - bye.data;
        }
    } else if(s->protocol == NGX_MAIL_POP3_PROTOCOL) {
        bye.data = ngx_palloc(c->pool, 
                       sizeof("-ERR ") - 1 +
                       msg.len +
                       sizeof(CRLF) - 1);
        if (bye.data == NULL) {
            ngx_str_set(&bye, "-ERR" CRLF);
        } else {
            p = bye.data;
            p = ngx_cpymem(p,"-ERR ",sizeof("-ERR ") - 1);
            p = ngx_cpymem(p, msg.data, msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p - bye.data;
        }
    } else {
        /* TODO SMTP is not (yet) relevant for zimbra, but how do we reject it ? */
        ngx_str_set(&bye, "");
    }

    s->out = bye;
    s->quit = 1;

    ngx_mail_send(c->write);

    return;
}

static void
ngx_mail_allow_session(throttle_callback_t *cb)
{
    ngx_connection_t            *c;
    ngx_mail_session_t          *s;
    ngx_mail_core_srv_conf_t    *cscf;

    c = (ngx_connection_t*)cb->connection;
    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    c->write->handler = ngx_mail_send;

    cscf->protocol->init_session(s, c);
}

static void
ngx_mail_choke_userauth(throttle_callback_t *cb)
{
    ngx_connection_t             *c;
    ngx_mail_session_t           *s;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_str_t                     bye, msg, umsg;
    size_t                        l;
    u_char                       *p;

    c = (ngx_connection_t *)cb->connection;
    s = c->data;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    msg = tscf->mail_login_user_rejectmsg;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
        "user throttle:%V choking mail session", &s->login);

    if(s->protocol == NGX_MAIL_IMAP_PROTOCOL)
    {
        bye.data = ngx_palloc(c->pool, sizeof("* BYE ") - 1 +
                              msg.len + sizeof(CRLF) - 1);
        if (bye.data == NULL) {
            ngx_str_set(&bye, "* BYE" CRLF);
        } else {
            p = bye.data;
            p = ngx_cpymem(p, "* BYE ", sizeof("* BYE ") - 1);
            p = ngx_cpymem(p, msg.data, msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p - bye.data;
        }
        s->out = bye;
        s->quit = 0;            /* don't quit just yet */
        ngx_mail_send(c->write);

        /* for IMAP, we also want to send back a tagged NO response */
        l = s->tag.len + 1 /*for space*/ +
            sizeof("NO ") - 1 +
            sizeof(" failed") - 1 +       /* ?? "failed" or "rejected" ?? */
            sizeof(CRLF) - 1;

        if (s->command == NGX_IMAP_LOGIN) {
            l += (sizeof("LOGIN ") - 1);
        } else if (s->command == NGX_IMAP_AUTHENTICATE) {
            l += (sizeof("AUTHENTICATE ") - 1);
        }

        umsg.data = ngx_palloc(c->pool,l);

        if (umsg.data == NULL) {
            ngx_str_set(&umsg, "");
        } else {
            p = umsg.data;
            p = ngx_cpymem(p, s->tag.data, s->tag.len);
            *p++=' ';
            p = ngx_cpymem(p, "NO ", sizeof("NO ") - 1);
            if (s->command == NGX_IMAP_LOGIN) {
                p = ngx_cpymem(p, "LOGIN ", sizeof("LOGIN ") - 1);
            } else if (s->command == NGX_IMAP_AUTHENTICATE) {
                p = ngx_cpymem(p, "AUTHENTICATE ", sizeof("AUTHENTICATE ") - 1);
            }
            p = ngx_cpymem(p, "failed", sizeof("failed") - 1);
            *p++ = CR;
            *p++ = LF;
            umsg.len = p - umsg.data;
        }

        s->out = umsg;
        s->quit = 1;
        ngx_mail_send(c->write);

        return;
    }
    else if(s->protocol == NGX_MAIL_POP3_PROTOCOL)
    {
        bye.data = 
        ngx_palloc(c->pool,
        sizeof("-ERR ")-1+msg.len+sizeof(CRLF)-1);
        if (bye.data == NULL) {
            bye.data = (u_char*)("-ERR" CRLF);
            bye.len = sizeof("-ERR" CRLF)-1;
        } else {
            p = bye.data;
            p = ngx_cpymem(p,"-ERR ",sizeof("-ERR ")-1);
            p = ngx_cpymem(p,msg.data,msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p-bye.data;
        }
        s->out = bye;
        s->quit = 1;
        ngx_mail_send(c->write);
        return;
    }
    else
    {
        /* TODO SMTP is not (yet) relevant for zimbra, but how do we reject it ? */
        ngx_str_set(&bye, "");
        s->out = bye;
        s->quit = 1;
        ngx_mail_send(c->write);
        return;
    }
}

static void
ngx_mail_allow_userauth(throttle_callback_t *cb)
{
    ngx_connection_t            *c;
    ngx_mail_session_t          *s;

    c = (ngx_connection_t *)cb->connection;
    s = c->data;

    /* remainder code is the erstwhile ngx_mail_do_auth(s);*/
    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;
    s->state = 0;

    if (s->connection->read->timer_set) {
        ngx_del_timer(s->connection->read);
    }

    s->login_attempt++;
    ngx_mail_zmauth_init(s);
}

ngx_int_t
ngx_mail_salt(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_mail_core_srv_conf_t *cscf)
{
    s->salt.data = ngx_pnalloc(c->pool,
                               sizeof("<18446744073709551616.@>" CRLF) - 1
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


/* Decode an SASL PLAIN challenge (RFC 4616)
   If AUTHZ is empty:
    set s->usedauth = 0, 
    set s->login = AUTHC
   If AUTHZ is present:
    set s->usedauth = 1
    set s->dusr = AUTHC
    set s->login = AUTHZ
 */
ngx_int_t
ngx_mail_auth_plain(ngx_mail_session_t *s, ngx_connection_t *c, ngx_uint_t n)
{
    u_char     *p, *last;
    ngx_str_t  *arg, plain, temp;

    arg = s->args.elts;

#if (NGX_MAIL_SSL)
    if(ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    /* check if the auth exchange is being aborted */
    if (s->args.nelts > 0 &&
        arg[n].len == 1 &&
        arg[n].data[0] == '*'
       )
    {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "auth:abort SASL PLAIN");

        ngx_mail_dispose_sasl_context(s);
        return NGX_MAIL_AUTH_ABORT;
    }

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\"", &arg[n]);
#endif

    plain.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
    if (plain.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&plain, &arg[n]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->auth_method = NGX_MAIL_AUTH_PLAIN;

    p = plain.data;
    last = p + plain.len;

    while (p < last && *p++) { /* void */ }

    if (p == last) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid login in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->dusr.data = plain.data;
    s->dusr.len = p - plain.data - 1;

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

    if (s->login.len > NGX_MAIL_MAX_LOGIN_LEN ||
        s->dusr.len > NGX_MAIL_MAX_LOGIN_LEN ||
        s->passwd.len > NGX_MAIL_MAX_PASSWORD_LEN) {
        return NGX_MAIL_AUTH_FAILED;
    }

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
#endif

    if (s->dusr.len == 0) {
        /* s->dusr = s->login; */
        s->usedauth = 0;
    } else {
        s->usedauth = 1;
        temp = s->dusr;
        s->dusr = s->login;
        s->login = temp;
    }

    s->dpasswd = s->passwd;

    return NGX_DONE;
}


ngx_int_t
ngx_mail_auth_login_username(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_uint_t n)
{
    ngx_str_t  *arg;

    arg = s->args.elts;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &arg[n]);

    /* check if the auth exchange is being aborted */
    if (s->args.nelts > 0 &&
        arg[n].len == 1 &&
        arg[n].data[0] == '*'
       )
    {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "auth:abort SASL LOGIN");

        ngx_mail_dispose_sasl_context(s);
        return NGX_MAIL_AUTH_ABORT;
    }

    if (ngx_base64_decoded_length(arg->len) > NGX_MAIL_MAX_LOGIN_LEN) {
        return NGX_MAIL_AUTH_FAILED;
    }
    s->login.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
    if (s->login.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&s->login, &arg[n]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &s->login);

    return NGX_MAIL_AUTH_ARGUMENT;
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
    /* check if the auth exchange is being aborted */
    if (s->args.nelts > 0 && 
        arg[0].len == 1 &&
        arg[0].data[0] == '*'
       ) {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "auth:abort SASL LOGIN");

        ngx_mail_dispose_sasl_context(s);
        return NGX_MAIL_AUTH_ABORT;
    }

    if(ngx_base64_decoded_length(arg[0].len) > NGX_MAIL_MAX_PASSWORD_LEN) {
        return NGX_MAIL_AUTH_FAILED;
    }
    s->passwd.data = ngx_pnalloc(c->pool,
                                 ngx_base64_decoded_length(arg[0].len));
    if (s->passwd.data == NULL) {
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

    s->auth_method = NGX_MAIL_AUTH_LOGIN;
    s->usedauth = 0;

    return NGX_DONE;
}


ngx_int_t
ngx_mail_auth_cram_md5_salt(ngx_mail_session_t *s, ngx_connection_t *c,
    char *prefix, size_t len)
{
    u_char      *p;
    ngx_str_t    salt;
    ngx_uint_t   n;

    p = ngx_pnalloc(c->pool, len + ngx_base64_encoded_length(s->salt.len) + 2);
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

    s->login.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[0].len));
    if (s->login.data == NULL) {
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
    s->usedauth = 0;

    return NGX_DONE;
}


ngx_int_t
ngx_mail_auth_gssapi(ngx_mail_session_t *s, ngx_connection_t *c, ngx_str_t * output)
{
    ngx_str_t  *args, *arg;
    ngx_uint_t narg;
    ngx_mail_core_srv_conf_t *cscf;
    int saslrc;

    args = s->args.elts;
    narg = s->args.nelts;
    arg = args + narg - 1;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    /* check if the auth exchange is being aborted */
    if (narg > 0 && 
        arg->len == 1 &&
        arg->data[0] == '*'
       )
    {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
            "auth:abort SASL GSSAPI");

        ngx_mail_dispose_sasl_context(s);
        return NGX_MAIL_AUTH_ABORT;
    }

    /* Initialize SASL once per process */
    saslrc = ngx_mail_initialize_sasl (c);

    if (saslrc != SASL_OK) {
        return NGX_ERROR;
    }

    /* create one sasl authentication object per connection */
    saslrc = ngx_mail_create_sasl_context (c);

    if (saslrc != SASL_OK) {
        return NGX_ERROR;
    }

    saslrc = ngx_mail_sasl_startstep(c,"gssapi", arg, output);

    if (saslrc == SASL_CONTINUE)
    {
        return NGX_MAIL_AUTH_ARGUMENT;
    }
    else if (saslrc == SASL_OK)
    {
        s->dusr = cscf->master_auth_username;
        s->dpasswd = cscf->master_auth_password;
        s->auth_method = NGX_MAIL_AUTH_GSSAPI;
        s->passwd = krb5_cooked_password;
        s->usedauth = 1;
        return NGX_DONE;
    }
    else
    {
        return NGX_ERROR;
    }
}

/* Perform a once-per-process initialization of the sasl library */
static int
ngx_mail_initialize_sasl (ngx_connection_t *c)
{
    ngx_mail_session_t          *s;
    ngx_mail_core_srv_conf_t    *cscf;
    int                          rc = SASL_OK;
    char                        *app;

    if (!sasl_initialized)
    {
        s = c->data;
        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        app = ngx_palloc(c->pool, cscf->sasl_app_name.len + 1);

        if (app == NULL) { return SASL_FAIL; }

        ngx_memcpy (app, cscf->sasl_app_name.data, cscf->sasl_app_name.len);
        ngx_memcpy (app + cscf->sasl_app_name.len, "\x0", 1);

        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "Initializing SASL library, app:%s", app);

        rc = sasl_server_init (NULL, app);

        if (rc != SASL_OK)
        {
            ngx_log_error (NGX_LOG_ERR, c->log, 0,
                "Cannot initialize SASL library: err:%d, %s",
                rc, sasl_errstring(rc,NULL,NULL)
            );
        }
        else
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "Initialized SASL library");
            sasl_initialized = 1;
        }
    }

    return rc;
}

static int
ngx_mail_sasl_pauthorize (sasl_conn_t *conn, void *context, const char *authz,
    unsigned authzlen, const char *authc, unsigned authclen, const char *realm,
    unsigned rlen, struct propctx *propctx)
{
    /* This function is called when we need to indicate whether the authz/authc
       relationship should be allowed or not i.e can authc access authz's mailbox
       since that decision must be made in the lookup servlet (which will happen later),
       we need to defer that decision to the route lookup phase, and simply indicate our consent here
     */

    ngx_connection_t    *c = context;
    ngx_str_t            nauthz = ngx_string(""),
                         nauthc = ngx_string(""),
                         nrealm = ngx_string("");

    (void)c;
    if (authz != NULL && authzlen > 0) {
        nauthz.data = (u_char *)authz;
        nauthz.len = authzlen;
    }
    if (authc != NULL && authclen > 0) {
        nauthc.data = (u_char *)authc;
        nauthc.len = authclen;
    }
    if (realm != NULL && rlen > 0) {
        nrealm.data = (u_char *)realm;
        nrealm.len = rlen;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_MAIL,c->log,0,
        "sasl: indicating proxy policy ok, authz:%V,authc:%V,realm:%V",
        &nauthz,&nauthc,&nrealm
        );

    return SASL_OK;
}

static int
ngx_mail_sasl_log (void *context, int level, const char *message)
{
    ngx_connection_t    *c = context;

    (void)c;
    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
        "%s", message == NULL ? "null" : message);

    return SASL_OK;
}


/* create a new SASL server authentication object (once per connection) */
static int
ngx_mail_create_sasl_context (ngx_connection_t *c)
{
    ngx_mail_session_t          *s;
    ngx_mail_core_srv_conf_t    *cscf;
    char                        *service;
    int                          rc = SASL_OK;
    sasl_security_properties_t   rsec;
    sasl_callback_t             *callbacks;
    ngx_uint_t                   i;
    const char                  *fqdn = NULL;
    struct hostent              *host;
    struct sockaddr_in           sa;
    socklen_t                    salen;
    u_char                      *octets;

    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (s->saslconn == NULL)
    {
        service = ngx_palloc (c->pool, cscf->sasl_service_name.len + 1);
        if (service == NULL) {
            return SASL_FAIL;
        }

        callbacks = ngx_palloc(c->pool,sizeof(sasl_callback_t) * 8);
        if (callbacks == NULL) {
            ngx_log_error (NGX_LOG_ERR, c->log, 0, 
                "cannot alloc memory for SASL callbacks"
                );
            return SASL_NOMEM;
        }

        i =0 ;

        callbacks[i].id = SASL_CB_LOG;
        callbacks[i].proc = (sasl_callback_ft)&ngx_mail_sasl_log;
        callbacks[i].context = c;
        ++i;

        callbacks[i].id = SASL_CB_PROXY_POLICY;
        callbacks[i].proc = (sasl_callback_ft)&ngx_mail_sasl_pauthorize;
        callbacks[i].context = c;
        ++i;

        callbacks[i].id = SASL_CB_LIST_END;
        callbacks[i].proc = NULL;
        callbacks[i].context = NULL;
        ++i;

        ngx_memcpy (service, cscf->sasl_service_name.data,
            cscf->sasl_service_name.len);
        service[cscf->sasl_service_name.len] = 0;

        /* The second argument to sasl_server_new is the FQDN of the server
           If the srvprinc_from_ip configuration parameter is true, then 
         */

        if (cscf->sasl_host_from_ip)
        {
            ngx_log_error (NGX_LOG_WARN, c->log, 0,
                "will use IP address to resolve service principal");

            salen = sizeof(sa);
            if (
                getsockname(s->connection->fd, (struct sockaddr*)&sa, &salen)
                == 0
               )
            {
                if (sa.sin_family != AF_INET || salen != sizeof(sa))
                {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "non-ipv4 local address of mail connection ignored");
                }
                else
                {
                    octets = (u_char *)&sa.sin_addr.s_addr;

                    ngx_log_error (NGX_LOG_WARN, c->log, 0,
                        "entering blocking network call (gethostbyaddr)");

                    host = gethostbyaddr(
                            &sa.sin_addr,
                            sizeof(sa.sin_addr),
                            AF_INET);

                    if (host == NULL)
                    {
                        ngx_log_error (NGX_LOG_ERR, c->log, 0,
                            "cannot lookup host by IP address, err:%d",
                            h_errno);
                    }
                    else
                    {
                        ngx_log_error (NGX_LOG_INFO, c->log, 0,
                            "resolved incoming IP %d.%d.%d.%d to host:%s",
                            octets[0],
                            octets[1],
                            octets[2],
                            octets[3],
                            host->h_name);

                        fqdn = host->h_name;
                    }
                }
            }
            else
            {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "cannot get local address of mail connection, err:%d",
                    ngx_errno);
            }
        }

        rc = sasl_server_new
                (
                    service,
                    fqdn,
                    NULL,
                    NULL,
                    NULL,
                    callbacks,
                    0,
                    &s->saslconn
                );

        if (rc != SASL_OK)
        {
            ngx_log_error (NGX_LOG_ERR, c->log, 0, 
                "cannot create SASL context (%V), err:%d,%s",
                &cscf->sasl_service_name,
                rc, sasl_errstring (rc,NULL,NULL)
                );
            s->saslconn = NULL;
        }
        else
        {
            const char * mechlist;
            unsigned     menLen;
            int          num;
            rc = sasl_listmech(s->saslconn, NULL, "{", ", ", "}", &mechlist, &menLen, &num);
            ngx_log_error(NGX_LOG_INFO, c->log,0, "mech list is: %s", mechlist);
            ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, c->log, 0, 
                "created SASL context (%V), 0x%p",
                &cscf->sasl_service_name,
                s->saslconn
                );

            rsec.min_ssf = 0;
            rsec.max_ssf = 0;
            rsec.maxbufsize = 4096;
            rsec.property_names = NULL;
            rsec.property_values = NULL;
            rsec.security_flags = 0;

            rc = sasl_setprop(s->saslconn, SASL_SEC_PROPS, &rsec);
        }
    }

    return rc;
}

static void
ngx_mail_dispose_sasl_context (ngx_mail_session_t *s)
{
    if (s->saslconn != NULL)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL,s->connection->log,0,
            "disposing SASL context:%p",s->saslconn);
        sasl_dispose(&s->saslconn);
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL,s->connection->log,0,
            "disposed SASL context:%p",s->saslconn);
        s->saslconn = NULL;
    }
    return;
}

static int
ngx_mail_sasl_startstep (
    ngx_connection_t *c,
    const char *mech,
    ngx_str_t  *response,
    ngx_str_t  *challenge
    )
{
    ngx_mail_session_t          *s;
    ngx_str_t                    r;
    int                          rc;
    const char                  *saslstr,*authc,*authz;
    unsigned                     sasls;
    ngx_str_t                    ch64, ch;
    ngx_mail_core_srv_conf_t    *cscf;
    u_char                      *p;
    ngx_flag_t                   inheritAuthZ, needRealm;
    size_t                       len;

    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s,ngx_mail_core_module);

    /* saslfr (fr = first response) indicates whether the client has
       issued at least one SASL response to the server
       saslfr starts out as 0, and is immediately set to 1 when the 
       server starts processing the client responses
     */
    if (!s->saslfr)
    {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "beginning SASL auth negotiation");

        if (response == NULL)
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "using NULL client response");

            r.data = NULL;
            r.len = 0;
        }
        else
        {
             ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "using response %V", response);

             r.len = ngx_base64_decoded_length (response->len);
             r.data = ngx_palloc (c->pool, r.len);

             if (r.data == NULL) {
                return SASL_FAIL;
             }

             if (ngx_decode_base64 (&r, response) != NGX_OK)
             {
                ngx_log_error (NGX_LOG_ERR, c->log, 0,
                    "invalid base64 response sent by client");

                return SASL_FAIL;
             }
             else
             {
                ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                    "%d bytes of base64-challenge decoded to %d sasl-bytes",
                    response->len, r.len);
             }
        }

        rc = sasl_server_start
                (
                    s->saslconn,
                    mech,
                    (char *)r.data,
                    r.len,
                    &saslstr,
                    &sasls
                );

        s->saslfr = 1;
    }
    else
    {
         ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "continuing SASL auth negotiation");

         r.len = ngx_base64_decoded_length (response->len);
         r.data = ngx_palloc (c->pool, r.len);

         if (r.data == NULL) {
            return SASL_FAIL;
         }

         if (ngx_decode_base64 (&r, response) != NGX_OK)
         {
            ngx_log_error (NGX_LOG_ERR, c->log, 0,
                "invalid base64 response sent by client");

            return SASL_FAIL;
         }
 
         rc = sasl_server_step
                (
                    s->saslconn,
                    (char *)r.data,
                    r.len,
                    &saslstr,
                    &sasls
                );
    }

    if ((rc != SASL_OK) && (rc != SASL_CONTINUE))
    {
        ngx_log_error (NGX_LOG_ERR, c->log, 0,
            "SASL auth negotiation failed, err:%d (%s)",
            rc, sasl_errstring(rc,NULL,NULL));
    }
    else
    {
        /* construct the challenge depending upon the protocol */

        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "constructing protocol specific response for %d bytes of challenge",
            sasls);

        if (saslstr == NULL || sasls == 0)
        {
            ch64.data = (u_char *)"";
            ch64.len = 0;
        }
        else
        {
            ch.len = sasls;
            ch.data = (u_char *)saslstr;

            ch64.len = ngx_base64_encoded_length(ch.len);
            ch64.data = ngx_palloc (c->pool, ch64.len);

            if (ch64.data == NULL) {
                return SASL_FAIL;
            }

            ngx_encode_base64 (&ch64, &ch);
        }

        if (rc == SASL_CONTINUE)
        {
            /* For IMAP/POP, we need to send "+" SP <challenge> CRLF */
            if (s->protocol == NGX_MAIL_IMAP_PROTOCOL ||
                s->protocol == NGX_MAIL_POP3_PROTOCOL
               )
            {
                challenge->len = sizeof("+ ") -1 + ch64.len + sizeof(CRLF) -1;
                challenge->data = ngx_palloc (c->pool,challenge->len);

                if (challenge->data == NULL) {
                    return SASL_FAIL;
                }

                memcpy (challenge->data,"+ ",sizeof("+ ") - 1);
                memcpy (challenge->data+sizeof("+ ")-1,ch64.data,ch64.len);
                memcpy (challenge->data+sizeof("+ ")-1+ch64.len,CRLF,
                        sizeof(CRLF)-1);
            }
            else
            {
                challenge->data = ch64.data;
                challenge->len = ch64.len;
            }
        }
        else  /* SASL_OK */
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "SASL auth negotiation complete");

            authc = NULL;
            authz = NULL;

            sasl_getprop(s->saslconn, SASL_AUTHUSER, (const void **)&authc);
            sasl_getprop(s->saslconn, SASL_USERNAME, (const void **)&authz);

            ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "sasl: authc=%s,authz=%s",
                authc == NULL ? "null" : authc,
                authz == NULL ? "null" : authz
            );

            /*  authc must always be present
                if authc doesn't end in @realm, then we append the default realm
                from the config file
             */

            /* s->login is authz if present, otherwise it is authc
             */

            if (authc == NULL)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_MAIL,c->log,0,
                    "sasl: cannot get authc, authentication will fail");
                rc = SASL_BADAUTH;
            }
            else
            {
                if (strrchr(authc,'@') == NULL) {
                    needRealm = 1;
                } else {
                    needRealm = 0;
                }

                if ((authz == NULL) || (ngx_strcmp(authc,authz) == 0)) {
                    inheritAuthZ = 1;
                } else {
                    inheritAuthZ = 0;
                }

                len = ngx_strlen(authc);

                if (needRealm) {
                    if (cscf->default_realm.len > 0) {
                        ngx_log_debug1(NGX_LOG_DEBUG_MAIL,c->log,0,
                            "No realm found in AUTHC, using config default %V", &cscf->default_realm);
                        len += (1 + cscf->default_realm.len);
                    } else {
                        ngx_log_error(NGX_LOG_ERR,c->log, 0,
                            "SASL realm required, but no realm found in authenticating principal");
                        ngx_log_error(NGX_LOG_ERR,c->log, 0,
                            "Authentication will fail. Set the `default_realm' variable to the default kerberos realm");
                    }
                }

                s->authid.data = ngx_palloc(c->pool,len);
                if (s->authid.data == NULL) {
                    s->authid.data = (u_char *)"";
                    s->authid.len = 0;
                    rc = SASL_NOMEM;
                } else {
                    s->authid.len = len;
                    p = s->authid.data;
                    p = ngx_cpymem (p,authc,strlen(authc));

                    if (needRealm) {
                        if (cscf->default_realm.len > 0) {
                            *p++ = '@';
                            p = ngx_cpymem (p,cscf->default_realm.data,cscf->default_realm.len);
                        }
                    }
                }

                if (inheritAuthZ) {
                    /* no separate authz was specified, or authz was same as authc
                       therefore the same changes made to authc must apply to authz
                     */
                    s->login.data = ngx_pstrdup(c->pool,&s->authid);
                    if (s->login.data == NULL) {
                        s->login.data = (u_char*)"";
                        s->login.len = 0;
                        rc = SASL_NOMEM;
                    } else {
                        s->login.len = s->authid.len;
                    }
                } else {
                    /* a separate authz was specified */
                    s->login.len  = ngx_strlen(authz);
                    s->login.data = ngx_palloc(c->pool,s->login.len);
                    if (s->login.data == NULL) {
                        s->login.data = (u_char*)"";
                        s->login.len = 0;
                        rc = SASL_NOMEM;
                    } else {
                        ngx_memcpy(s->login.data,authz,s->login.len);
                    }
                }
            }

            if(rc == SASL_OK)
            {
                ngx_log_debug2(NGX_LOG_DEBUG_MAIL,c->log,0,
                    "sasl: auth exchange completed, login:%V, authc:%V", 
                    &s->login, &s->authid);
            }

            /* we don't need the SASL object after authentication because
               we don't negotiate a security layer with any ssf 
             */

            ngx_mail_dispose_sasl_context(s);
        }
    }

    return rc;
}


ngx_int_t
ngx_mail_auth_external(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_uint_t n)
{
    ngx_str_t  *arg, external;

    arg = s->args.elts;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &arg[n]);

    external.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
    if (external.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&external, &arg[n]) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH EXTERNAL command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = external.len;
    s->login.data = external.data;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &s->login);

    s->auth_method = NGX_MAIL_AUTH_EXTERNAL;

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
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_mail_close_connection(c);
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.data += n;
        s->out.len -= n;

        if (s->out.len != 0) {
            goto again;
        }

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        if (s->quit) {
            ngx_mail_end_session(s);
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

again:

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_mail_close_connection(c);
        return;
    }
}


void
ngx_mail_do_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    throttle_callback_t          *callback;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_mail_zmauth_conf_t   *zmcf;

    zmcf = (ngx_mail_zmauth_conf_t *)ngx_mail_get_module_srv_conf(s, ngx_mail_zmauth_module);
    if (zmcf->use_zmauth != 1) {
        s->qlogin = s->login;
        ngx_mail_auth(s, c);
        return;
    }

    /* all auth mechanisms for all protocols pass through ngx_mail_do_auth()
       here. Therefore, it is best to just look at the zimbra extensions 
       *once* at this point, rather than peppering that code all across 
     */

    if (has_zimbra_extensions(s->login)) {
        s->zlogin = get_zimbra_extension(s->login);
        s->login.len -= s->zlogin.len;
    } else {
        s->zlogin.data = (u_char *)"";
        s->zlogin.len = 0;
    }

    if (s->usedauth)
    {
        if (has_zimbra_extensions(s->dusr)) {
            s->zusr = get_zimbra_extension(s->dusr);
            s->dusr.len -= s->zusr.len;
        } else {
            s->zusr.data = (u_char *)"";
            s->zusr.len = 0;
        }
    }

    if (s->usedauth) {
        /* technically, zimbra extensions are not allowed in authc
           but it is too troublesome to reject the login appropriately
           at this point (with the correct message), therefore it is 
           less bother to just pass the authc + {wm,ni,tb} to upstream
         */
        if (s->login.len == s->dusr.len &&
            ngx_memcmp(s->login.data, s->dusr.data, s->login.len) == 0) {
            s->qualifydauth = 1;
        }
    }

    callback = ngx_pcalloc(c->pool, sizeof(throttle_callback_t));
    if (callback == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    callback->check_only = 1;    /* just check the counter's value */
    callback->session = s;
    callback->connection = c;
    callback->log = ngx_cycle->log;
    callback->pool = c->pool;
    callback->on_allow = ngx_mail_allow_userauth;
    callback->on_deny = ngx_mail_choke_userauth;

    /* because of DOS attacks against legitimate users, throttling is 
       postponed till after authentication
     */
    tscf = ngx_mail_get_module_srv_conf (s, ngx_mail_throttle_module);
    if (tscf->mail_login_user_max == 0) {
        callback->on_allow(callback);
    } else {
        ngx_mail_throttle_user(s->login, callback);
    }

    /* previous body of ngx_mail_do_auth() now in ngx_mail_allow_userauth */
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
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        if (s->buffer->pos == s->buffer->last) {
            return NGX_AGAIN;
        }
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

    if (s->buffer->pos == s->buffer->last) {
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
    }

    s->state = 0;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    s->login_attempt++;

    ngx_mail_auth_http_init(s);
}


/* send a protocol-suitable internal error message to downstream
   close the downstream connection immediately afterwards
 */
void
ngx_mail_session_internal_server_error(ngx_mail_session_t *s)
{
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_connection_t          *c;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    s->out = cscf->protocol->internal_server_error;

    c = s->connection->write->data;
    ngx_mail_send(s->connection->write);
    if (c->destroyed) {
        return;
    }
    /* clean up */
    ngx_mail_cleanup_t * cln = s->cleanup;
    while (cln != NULL) {
        cln->handler(cln->data);
        cln = cln->next;
    }

    ngx_mail_close_connection (s->connection);
}


/* send a protocol-suitable bye message to downstream
   close the downstream connection immediately afterwards
 */
void
ngx_mail_end_session(ngx_mail_session_t *s)
{
    ngx_str_t            bye = ngx_mail_session_getquitmsg(s);
    ngx_connection_t    *c = s->connection;

    if (bye.len > 0) {
        c->send(c, bye.data, bye.len);
    }

    /* clean up */
    ngx_mail_cleanup_t * cln = s->cleanup;
    while (cln != NULL) {
        cln->handler(cln->data);
        cln = cln->next;
    }

    ngx_mail_close_connection (c);
}

/* return protocol-specific bye message */
ngx_str_t ngx_mail_session_getquitmsg(ngx_mail_session_t *s)
{
    ngx_mail_core_srv_conf_t *cscf;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    return cscf->protocol->quit_msg;
}

/* return protocol-specific internal error message */
ngx_str_t ngx_mail_session_geterrmsg(ngx_mail_session_t *s)
{
    ngx_mail_core_srv_conf_t  *cscf;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    return cscf->protocol->internal_server_error;
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
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


/* note -- we want to log the local and remote host/port information for the 
   mail proxy sessions. however, nginx allows a mail servers to be specified as
   listening on a unix domain socket. the code below assumes that the sockaddr
   structure is pointing to an IPv4 address, and prints the address information
   accordingly. we will need to modify the code in case we want to support
   printing of unix domain socket information 
 */
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

    if (ctx->client_port && ctx->client_port < 65536) {
        p = ngx_snprintf(buf, len, ", client: %V:%ui", ctx->client, ctx->client_port);
    } else {
        p = ngx_snprintf(buf, len, ", client: %V", ctx->client, ctx->client_port);
    }
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

    /* with proxy, output the proxy relationship */

    u_char               dw_host[NGX_SOCKADDRLEN],
                         dw_peer[NGX_SOCKADDRLEN],
                         up_host[NGX_SOCKADDRLEN],
                         up_peer[NGX_SOCKADDRLEN];

    socklen_t            dw_host_len, dw_peer_len,
                         up_host_len, up_peer_len,
                         n;

    ngx_memzero (dw_peer, NGX_SOCKADDRLEN);
    ngx_memzero (dw_host, NGX_SOCKADDRLEN);
    ngx_memzero (up_host, NGX_SOCKADDRLEN);
    ngx_memzero (up_peer, NGX_SOCKADDRLEN);

    dw_host_len = dw_peer_len = up_host_len = up_peer_len = NGX_SOCKADDRLEN;

    if (s->connection) {
       getsockname
            (s->connection->fd, (struct sockaddr *)dw_host, &dw_host_len);

       getpeername
            (s->connection->fd, (struct sockaddr *)dw_peer, &dw_peer_len);
    }

    if (s->proxy->upstream.connection) {
        getsockname (s->proxy->upstream.connection->fd,
            (struct sockaddr *)up_host, &up_host_len);
        getpeername (s->proxy->upstream.connection->fd,
            (struct sockaddr *)up_peer, &up_peer_len);
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    len -= p - buf;
    buf = p;

    /* generate "(dw_peer->dw_host) <=> (up_host->up_peer)" */
    p = ngx_snprintf(buf, len, " (");
    len -= p - buf;
    buf = p;

    n = ngx_sock_ntop((struct sockaddr *)dw_peer, dw_peer_len, buf, len, 1);
    len -= n;
    buf += n;

    *buf++ = '-';
    len--;
    *buf++ = '>';
    len--;

    n = ngx_sock_ntop((struct sockaddr *)dw_host, dw_host_len, buf, len, 1);
    len -= n;
    buf += n;

    p = ngx_snprintf(buf, len, ") <=> (");
    len -= p - buf;
    buf = p;

    n = ngx_sock_ntop((struct sockaddr *)up_host, up_host_len, buf, len, 1);
    len -= n;
    buf += n;

    *buf++ = '-';
    len--;
    *buf++ = '>';
    len--;

    n = ngx_sock_ntop((struct sockaddr *)up_peer, up_peer_len, buf, len, 1);
    len -= n;
    buf += n;

    *buf++ = ')';
    len--;

    p = buf;

    return p;
}


/*
 * Giving a socket, return its local addr string representation IP. The
 * string will be allocated on "pool".
 */
ngx_str_t ngx_mail_get_socket_local_addr_str (ngx_pool_t *pool, ngx_socket_t s)
{
    int family;
    static ngx_str_t     res;
    struct sockaddr_in  *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif
    u_char              *p;
    socklen_t            len, strlen;
    u_char               sockaddr[NGX_SOCKADDRLEN];

    len = NGX_SOCKADDRLEN;
    ngx_memzero(sockaddr, len);
    getsockname(s, (struct sockaddr*)sockaddr, &len);

    family = ((struct sockaddr *)sockaddr)->sa_family;
    if (family == AF_INET) {
        sin = (struct sockaddr_in *)sockaddr;
        p = ngx_palloc(pool, NGX_INET_ADDRSTRLEN);
        strlen = ngx_inet_ntop (family, &(sin->sin_addr.s_addr), p,
                NGX_INET_ADDRSTRLEN);

#if (NGX_HAVE_INET6)
    } else {
        sin6 = (struct sockaddr_in6 *)sockaddr;
        p = ngx_palloc(pool, NGX_INET6_ADDRSTRLEN);
        strlen = ngx_inet_ntop (family, &(sin6->sin6_addr.s6_addr),
                p, NGX_INET6_ADDRSTRLEN);
#endif

    }

    res.data = p;
    res.len = strlen;

    return res;
}
