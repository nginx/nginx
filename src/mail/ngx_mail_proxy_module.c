
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_mail.h>
#include <ngx_mail_throttle_module.h>
#include <ngx_mail_pop3_module.h>
#include <ngx_mail_imap_module.h>
#include <ngx_mail_smtp_module.h>
#include <ngx_zm_lookup.h>

extern ngx_module_t ngx_mail_auth_http_module;

typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  pass_error_message;
    ngx_flag_t  issue_pop3_xoip;
    ngx_flag_t  issue_imap_id;
    ngx_flag_t  xclient;
    ngx_flag_t  proxy_ssl;
    ngx_ssl_t  *ssl;
    size_t      buffer_size;
    ngx_msec_t  ctimeout;
    ngx_msec_t  timeout;
} ngx_mail_proxy_conf_t;


static void ngx_mail_proxy_block_read(ngx_event_t *rev);
static void ngx_mail_proxy_pop3_handler(ngx_event_t *rev);
static void ngx_mail_proxy_imap_handler(ngx_event_t *rev);
static void ngx_mail_proxy_smtp_handler(ngx_event_t *rev);
static void ngx_mail_proxy_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_mail_proxy_read_response(ngx_mail_session_t *s,
    ngx_uint_t state);
static void ngx_mail_proxy_handler(ngx_event_t *ev);
static void ngx_mail_proxy_upstream_error(ngx_mail_session_t *s);
static void ngx_mail_proxy_internal_server_error(ngx_mail_session_t *s);
static void ngx_mail_proxy_close_session(ngx_mail_session_t *s);
static void *ngx_mail_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_mail_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

#if (NGX_MAIL_SSL)
static char *ngx_mail_proxy_ssl(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_mail_proxy_ssl_init_connection(ngx_mail_session_t *s,
        ngx_connection_t *c);
static void ngx_mail_proxy_ssl_handshake(ngx_connection_t *c);
/** TODO suport ssl session reuse
static void ngx_mail_proxy_set_session(ngx_peer_connection_t *pc);
static void ngx_mail_proxy_save_session(ngx_peer_connection_t *pc);
*/
#endif

/* throttle */
static void ngx_mail_proxy_throttle_imap(ngx_event_t *rev);
static void ngx_mail_proxy_allow_imap(throttle_callback_t *callback);
static void ngx_mail_proxy_choke_imap(throttle_callback_t *callback);
static void ngx_mail_proxy_throttle_pop3(ngx_event_t *rev);
static void ngx_mail_proxy_allow_pop3(throttle_callback_t *callback);
static void ngx_mail_proxy_choke_pop3(throttle_callback_t *callback);
static void ngx_mail_proxy_choke_session(ngx_mail_session_t *s);

/* utility */
static ngx_str_t ngx_imap_quote_string(ngx_pool_t *pool, ngx_str_t *u);
static void ngx_mail_proxy_auth_sleep_handler (ngx_event_t *rev);


static ngx_command_t  ngx_mail_proxy_commands[] = {

    { ngx_string("proxy"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, enable),
      NULL },

    { ngx_string("proxy_buffer"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_ctimeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, ctimeout),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, timeout),
      NULL },

    { ngx_string("proxy_pass_error_message"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, pass_error_message),
      NULL },

    { ngx_string("proxy_issue_pop3_xoip"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, issue_pop3_xoip),
      NULL },

    { ngx_string("proxy_issue_imap_id"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, issue_imap_id),
      NULL },

    { ngx_string("xclient"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, xclient),
      NULL },

#if (NGX_MAIL_SSL)

    { ngx_string("proxy_ssl"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_mail_proxy_ssl,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, proxy_ssl),
      NULL },

#endif

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_proxy_create_conf,            /* create server configuration */
    ngx_mail_proxy_merge_conf              /* merge server configuration */
};


ngx_module_t  ngx_mail_proxy_module = {
    NGX_MODULE_V1,
    &ngx_mail_proxy_module_ctx,            /* module context */
    ngx_mail_proxy_commands,               /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static u_char  pop3_authplain[] = "AUTH PLAIN" CRLF;
static u_char  pop3_authxzimbra[] = "AUTH X-ZIMBRA" CRLF;
static u_char  smtp_auth_ok[] = "235 2.0.0 OK" CRLF;
static u_char  imap_login_no[] = "NO LOGIN failed" CRLF;
static u_char  imap_auth_no[] = "NO AUTHENTICATE failed" CRLF;
static u_char  imap_no[] = "NO" CRLF;


void
ngx_mail_proxy_init(ngx_mail_session_t *s, ngx_addr_t *peer)
{
    ngx_int_t                  rc;
    ngx_mail_proxy_ctx_t      *p;
    ngx_mail_proxy_conf_t     *pcf;
    ngx_mail_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    p = ngx_pcalloc(s->connection->pool, sizeof(ngx_mail_proxy_ctx_t));
    if (p == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.sockaddr = peer->sockaddr;
    p->upstream.socklen = peer->socklen;
    p->upstream.name = &peer->name;
    p->upstream.get = ngx_event_get_peer;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&p->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

    ngx_add_timer(p->upstream.connection->read, pcf->ctimeout);

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_mail_proxy_block_read;
    p->upstream.connection->write->handler = ngx_mail_proxy_dummy_handler;

    s->proxy->buffer = ngx_create_temp_buf(s->connection->pool,
                                           pcf->buffer_size);
    if (s->proxy->buffer == NULL) {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->out.len = 0;

/* bug 32683, ssl support on mail proxy connection */
#if (NGX_MAIL_SSL)

    if (pcf->proxy_ssl && p->upstream.connection->ssl == NULL) {
        ngx_mail_proxy_ssl_init_connection(s, p->upstream.connection);
        return;
    }

#endif

    switch (s->protocol) {

    case NGX_MAIL_POP3_PROTOCOL:
        p->upstream.connection->read->handler = ngx_mail_proxy_pop3_handler;
        s->mail_state = ngx_pop3_start;
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        p->upstream.connection->read->handler = ngx_mail_proxy_imap_handler;
        s->mail_state = ngx_imap_start;
        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */
        p->upstream.connection->read->handler = ngx_mail_proxy_smtp_handler;
        s->mail_state = ngx_smtp_start;
        break;
    }
}


static void
ngx_mail_proxy_block_read(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_mail_proxy_close_session(s);
    }
}


static void
ngx_mail_proxy_pop3_handler(ngx_event_t *rev)
{
    u_char                 *p;
    ngx_int_t               rc;
    int                     family;
    ngx_str_t               line;
    size_t                  len;
    ngx_connection_t       *c;
    ngx_mail_session_t     *s;
    ngx_mail_proxy_conf_t  *pcf;
    struct sockaddr_in     *sin;

#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
#endif

    ngx_mail_core_srv_conf_t   *cscf;
    ngx_str_t                   ap, ap64, tmp;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy pop3 auth handler");

    c = rev->data;
    s = c->data;

    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    rc = ngx_mail_proxy_read_response(s, s->mail_state);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        if (s->mail_state == ngx_pop3_passwd ||
            s->mail_state == ngx_pop3_auth_plain_response
           )
        {
            if(s->proxy->upstream.connection->read->timer_set) {
                ngx_del_timer(s->proxy->upstream.connection->read);
            }

            ngx_add_timer(s->connection->read,cscf->auth_wait_intvl);
            s->connection->read->handler = ngx_mail_proxy_auth_sleep_handler;
            return;
        }
        else
        {
            ngx_mail_proxy_upstream_error(s);
            return;
        }
    }

    if (s->mail_state == ngx_pop3_start)
    {
        // bug 23349 -- conditionally (not always) issue pop3 xoip command
        if (pcf->issue_pop3_xoip == 0) {
            s->mail_state = ngx_pop3_xoip;
        }
    }

    switch (s->mail_state) {

    case ngx_pop3_start:
        s->connection->log->action = 
            "sending POP3 XOIP command to upstream";

        /* Bug 13325 - The upstream server needs to record the IP address of
           the downstream client that connected. For this, the Zimbra server
           has been modified to support the XOIP command that will allow 
           the proxy to pass the IP address of the downstream client. Both
           ipv4 and ipv6 (bug 56383) has been supported
         */
        family = s->connection->sockaddr->sa_family;
        if (family == AF_INET) {
            len = NGX_INET_ADDRSTRLEN;
            sin = (struct sockaddr_in *) s->connection->sockaddr;

#if (NGX_HAVE_INET6)
        } else { /* AF_INET6 */
            len = NGX_INET6_ADDRSTRLEN;
            sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
#endif

        }

        line.len = sizeof ("XOIP ") -1 +
                len +
                sizeof (CRLF) - 1;

        line.data = ngx_palloc(c->pool, line.len);

        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_sprintf (line.data, "XOIP ");
        tmp.data = p;

        if (family == AF_INET) {
            len = ngx_inet_ntop (family, &(sin->sin_addr.s_addr), p,
                    line.data + line.len - p);

#if (NGX_HAVE_INET6)
        } else { /* AF_INET6 */
            len = ngx_inet_ntop (family, &(sin6->sin6_addr.s6_addr),
                    p, line.data + line.len - p);
#endif

        }

        p += len;

        tmp.len = p - tmp.data;

        *p++ = CR;
        *p++ = LF;

        line.len = p - line.data;

        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, rev->log, 0,
            "sending POP3 XOIP command (XOIP %V)",
            &tmp);

        s->mail_state = ngx_pop3_xoip;

        break;

    case ngx_pop3_xoip:
        if (!s->usedauth && (s->auth_method == NGX_MAIL_AUTH_PLAIN
                || s->auth_method == NGX_MAIL_AUTH_PLAIN_IR))
        {
            /* If auth plain was used, but no authz, then we must blank out
               login+zlogin, and use dusr+zusr in authc to upstream
             */
            s->dusr = s->qlogin;
            s->zusr = s->zlogin;
            s->qlogin.data = (u_char*)"";
            s->qlogin.len = 0;
            s->zlogin.data = (u_char*)"";
            s->zlogin.len = 0;
            s->usedauth = 1;
        }

        if (!s->usedauth)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                "mail proxy send user");

            s->connection->log->action = "sending user name to upstream";

            line.len = sizeof("USER ")  - 1 + s->qlogin.len + 2;
            line.data = ngx_palloc(c->pool, line.len);
            if (line.data == NULL) {
                ngx_mail_proxy_internal_server_error(s);
                return;
            }

            p = ngx_cpymem(line.data, "USER ", sizeof("USER ") - 1);
            p = ngx_cpymem(p, s->qlogin.data, s->qlogin.len);
            *p++ = CR; *p = LF;

            s->mail_state = ngx_pop3_user;
        }
        else
        {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                    "mail proxy send auth plain");

            if (s->auth_method == NGX_MAIL_AUTH_GSSAPI)
            {
                s->connection->log->action = "sending AUTH X-ZIMBRA to upstream";
                line.len = sizeof(pop3_authxzimbra) -1;
                line.data = pop3_authxzimbra;
            }
            else
            {
                s->connection->log->action = "sending AUTH PLAIN to upstream";
                line.len = sizeof(pop3_authplain) - 1;
                line.data = pop3_authplain;
            }

            s->mail_state = ngx_pop3_auth_plain;
        }

        break;

    case ngx_pop3_user:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send pass");

        s->connection->log->action = "sending password to upstream";

        line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
        p = ngx_cpymem(p, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_pop3_passwd;
        break;

    case ngx_pop3_passwd:
    case ngx_pop3_auth_plain_response:
        ngx_mail_proxy_throttle_pop3(rev);
        return;

    case ngx_pop3_auth_plain:
        if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                "mail proxy send AUTH X-ZIMBRA response");
            s->connection->log->action = "sending AUTH X-ZIMBRA response to upstream";
        }
        else {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                "mail proxy send AUTH PLAIN response");
            s->connection->log->action = "sending AUTH PLAIN response to upstream";
        }


        ap.len = s->qlogin.len + 1 +
                 s->dusr.len + 1 +
                 s->dpasswd.len;
        ap.data = ngx_palloc (c->pool, ap.len);

        if (ap.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        ngx_memcpy (ap.data, s->qlogin.data, s->qlogin.len);
        ngx_memcpy (ap.data + s->qlogin.len, "\x0", 1);
        ngx_memcpy (ap.data + s->qlogin.len + 1,
                    s->dusr.data,
                    s->dusr.len);
        ngx_memcpy (ap.data + s->qlogin.len + 1 + s->dusr.len,
                    "\x0",1);
        ngx_memcpy (ap.data + s->qlogin.len+1 + s->dusr.len + 1,
                    s->dpasswd.data,
                    s->dpasswd.len);

        ap64.len = ngx_base64_encoded_length(ap.len);
        ap64.data = ngx_palloc(c->pool, ap64.len);

        if (ap64.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        ngx_encode_base64 (&ap64, &ap);

        line.len = ap64.len + sizeof(CRLF) -1;
        line.data = ngx_palloc (c->pool, line.len);

        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        ngx_memcpy (line.data, ap64.data, ap64.len);
        ngx_memcpy (line.data + ap64.len, CRLF, sizeof (CRLF) -1);

        s->mail_state = ngx_pop3_auth_plain_response;
        break;

    default:
#if (NGX_SUPPRESS_WARN)
        ngx_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_mail_proxy_imap_handler(ngx_event_t *rev)
{
    u_char                 *p;
    ngx_int_t               rc;
    ngx_uint_t              family;
    size_t                  len;
    ngx_str_t               line, proxy_ip;
    ngx_connection_t       *c;
    ngx_mail_session_t     *s;
    ngx_mail_proxy_conf_t  *pcf;
    struct sockaddr_in     *sin;

#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    ngx_mail_core_srv_conf_t   *cscf;
    ngx_mail_imap_srv_conf_t   *iscf;
    ngx_str_t                   challenge;
    ngx_str_t                   ql, qp, login, tmp;
    socklen_t                   socklen;
    u_char                      sockaddr[NGX_SOCKADDRLEN];

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy imap auth handler");

    c = rev->data;
    s = c->data;
    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    rc = ngx_mail_proxy_read_response(s, s->mail_state);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ABORT) {
        /* NGX_ABORT is borrowed to indicate nginx should send
         * something coming from upstream directly. But don't return
         * just yet as we need to replay all other responses from
         * the upstream as well
         */
        if (s->connection->send(s->connection, s->out.data, s->out.len) <
                (ssize_t) s->out.len) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }
        s->proxy->buffer->pos = s->proxy->buffer->start;
        s->proxy->buffer->last = s->proxy->buffer->start;
    }

    if (rc == NGX_ERROR) {
        if (s->mail_state == ngx_imap_passwd ||
            s->mail_state == ngx_imap_auth_plain_ir
           )
        {
            if(s->proxy->upstream.connection->read->timer_set) {
                ngx_del_timer(s->proxy->upstream.connection->read);
            }

            ngx_add_timer(s->connection->read,cscf->auth_wait_intvl);
            s->connection->read->handler = ngx_mail_proxy_auth_sleep_handler;
            return;
        }
        else
        {
            ngx_mail_proxy_upstream_error(s);
            return;
        }
    }

    if (s->mail_state == ngx_imap_start)
    {
        // bug 23349 -- conditionally (not always) issue imap id command
        if (pcf->issue_imap_id == 0) {
            s->mail_state = ngx_imap_id;
        }
    }

    switch (s->mail_state) {

    case ngx_imap_start:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send id");
                       
        s->connection->log->action = 
            "sending IMAP ID extension command to upstream";

        /* Bug 13325 - The upstream server needs to record the IP of the
           original downstream client that connected, not just the proxy's IP
           To pass on the information about the downstream client, we use the
           IMAP ID extension command (rfc 2971)

           Currently both ipv4 and ipv6 (bug 56383) are supported
         */
        family = s->connection->sockaddr->sa_family;
        if (family == AF_INET) {
            len = NGX_INET_ADDRSTRLEN;
            sin = (struct sockaddr_in *) s->connection->sockaddr;

#if (NGX_HAVE_INET6)
        } else { /* AF_INET6 */
            len = NGX_INET6_ADDRSTRLEN;
            sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
#endif

        }

        line.len = s->tag.len + 1 /* for space */ +
                sizeof ("ID (\"X-ORIGINATING-IP\" \"") - 1 +
                len +
                sizeof ("\" \"name\" \"") - 1 +
                iscf->ua_name.len +
                sizeof("\" \"version\" \"") - 1 +
                iscf->ua_version.len +
                sizeof ("\" \"X-VIA\" \"(" NGINX_VER ")\")"CRLF) - 1;
        ngx_memzero(sockaddr, NGX_SOCKADDRLEN);
        socklen = NGX_SOCKADDRLEN;
        if(getsockname(s->connection->fd, (struct sockaddr*)sockaddr, &socklen) < 0) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, errno, "can't get proxy's IP address");
        }

        if(((struct sockaddr *)sockaddr)->sa_family == AF_INET) {
            proxy_ip.len = NGX_INET_ADDRSTRLEN;
        } else {
            proxy_ip.len = NGX_INET6_ADDRSTRLEN;
        }
        proxy_ip.data = ngx_palloc(c->pool, proxy_ip.len);
        proxy_ip.len = ngx_sock_ntop((struct sockaddr*)sockaddr, socklen, proxy_ip.data, proxy_ip.len, 0);
        line.len += proxy_ip.len;

        if (s->id_name.len > 0) {
            line.len += (s->id_name.len + sizeof(",") - 1);
            if (s->id_version.len > 0) {
                line.len += (s->id_version.len + sizeof("/") - 1);
            }
        }

        line.data = ngx_palloc(c->pool, line.len);

        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_sprintf (line.data, "%V ID (\"X-ORIGINATING-IP\" \"", &s->tag);
        tmp.data = p;

        if (family == AF_INET) {
            len = ngx_inet_ntop (family, &(sin->sin_addr.s_addr), p,
                    line.data + line.len - p);
#if (NGX_HAVE_INET6)
        } else { /* AF_INET6 */
            len = ngx_inet_ntop (family, &(sin6->sin6_addr.s6_addr),
                    p, line.data + line.len - p);
#endif
        }

        p += len;
        tmp.len = p - tmp.data;

        p = ngx_sprintf(p, "\" \"name\" \"%V\" \"version\" \"%V\" \"X-VIA\" \"",
                        &iscf->ua_name, &iscf->ua_version);
        if (s->id_name.len > 0) {
            p = ngx_cpymem(p, s->id_name.data, s->id_name.len);
            if (s->id_version.len > 0) {
                *p++ = '/';
                p = ngx_cpymem(p, s->id_version.data, s->id_version.len);
            }
            *p++ = ',';
        }
        p = ngx_sprintf(p, "%V(" NGINX_VER ")\")"CRLF, &proxy_ip);

        line.len = p - line.data;

        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                "sending IMAP ID command %V",
                &line);

        s->mail_state = ngx_imap_id;

        break;

    case ngx_imap_id:
        /* If the downstream client has logged in with a sasl mechanism 
           that does not use clear-text passwords, we do not have the 
           end user credentials to log in to the upstream server, therefore
           in this case, we need to log in with the master username and 
           master password, using auth plain to the upstream server
         */

        if (!s->usedauth && (s->auth_method == NGX_MAIL_AUTH_PLAIN
                || s->auth_method == NGX_MAIL_AUTH_PLAIN_IR)) {
            /* If auth plain was used, but no authz, then we must blank out
               login+zlogin, and use dusr+zusr in authc to upstream
             */
            s->dusr = s->qlogin;
            s->zusr = s->zlogin;
            s->qlogin.data = (u_char*)"";
            s->qlogin.len = 0;
            s->zlogin.data = (u_char*)"";
            s->zlogin.len = 0;
            s->usedauth = 1;
        }

        if (!s->usedauth)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "no delegated auth, login to upstream using LOGIN");

            s->connection->log->action = "sending LOGIN command to upstream";

            /* LOGIN with literal or quoted strings (imap_literalauth) */
            if (iscf->literalauth)
            {
                line.len = s->tag.len + 1 + sizeof("LOGIN ") - 1
                           + 1 + NGX_SIZE_T_LEN + 1 + 2;
                line.data = ngx_palloc(c->pool, line.len);
                if (line.data == NULL) {
                    ngx_mail_proxy_internal_server_error(s);
                    return;
                }

                line.len = ngx_sprintf(line.data, "%V LOGIN {%uz}" CRLF,
                                       &s->tag, s->qlogin.len + s->zlogin.len)
                           - line.data;

                s->mail_state = ngx_imap_login;
            }
            else
            {
                /* merge back zimbra extensions (/tb|/wm|/ni), if any */

                login.data = ngx_palloc(c->pool, s->qlogin.len + s->zlogin.len);
                if (login.data == NULL) {
                    login = s->qlogin;
                } else {
                    login.len = s->qlogin.len + s->zlogin.len;
                    ngx_memcpy(login.data, s->qlogin.data, s->qlogin.len);
                    ngx_memcpy(login.data + s->qlogin.len, s->zlogin.data,
                               s->zlogin.len);
                }
                ql = ngx_imap_quote_string(c->pool, &login);
                qp = ngx_imap_quote_string(c->pool, &s->passwd);

                line.len = s->tag.len + 1 /* for space */ + sizeof("LOGIN ") - 1 +
                           ql.len + 
                           sizeof(" ") - 1 +
                           qp.len +
                           sizeof(CRLF) - 1;

                line.data = ngx_palloc(c->pool,line.len);
                if (line.data == NULL) {
                    ngx_mail_proxy_internal_server_error(s);
                    return;
                }

                ngx_sprintf(line.data,"%V LOGIN %V %V" CRLF, &s->tag, &ql, &qp);

                s->mail_state = ngx_imap_passwd;
            }
        }
        else
        {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                "Using delegated auth to log in to upstream");

            if (s->auth_method == NGX_MAIL_AUTH_GSSAPI)
            {
                s->connection->log->action = "sending AUTHENTICATE X-ZIMBRA to upstream";

                line.len = s->tag.len + 1 /* for space */ + sizeof ("AUTHENTICATE X-ZIMBRA") - 1 + 2;
                line.data = ngx_palloc (c->pool, line.len);

                if (line.data == NULL) {
                    ngx_mail_proxy_internal_server_error(s);
                    return;
                }

                ngx_snprintf (line.data, line.len, "%V AUTHENTICATE X-ZIMBRA" CRLF, &s->tag);
            }
            else
            {
                s->connection->log->action = "sending AUTHENTICATE PLAIN to upstream";

                line.len = s->tag.len + 1 /* for space */ + sizeof ("AUTHENTICATE PLAIN") - 1 + 2;
                line.data = ngx_palloc (c->pool, line.len);

                if (line.data == NULL) {
                    ngx_mail_proxy_internal_server_error(s);
                    return;
                }

                ngx_snprintf (line.data, line.len, "%V AUTHENTICATE PLAIN" CRLF, &s->tag);
            }

            s->mail_state = ngx_imap_auth_plain;
        }
        break;

    case ngx_imap_login:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = s->qlogin.len + 1 + 1 + NGX_SIZE_T_LEN + 1 + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data, "%V%V {%uz}" CRLF,
                               &s->qlogin, &s->zlogin, s->passwd.len)
                   - line.data;

        s->mail_state = ngx_imap_user;
        break;

    case ngx_imap_user:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send passwd");

        s->connection->log->action = "sending password to upstream";

        line.len = s->passwd.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_imap_passwd;
        break;

    case ngx_imap_passwd:
    case ngx_imap_auth_plain_ir:
        ngx_mail_proxy_throttle_imap(rev);
        return;

    case ngx_imap_auth_plain:
        /* RFC 4616
           message   = [authzid] UTF8NUL authcid UTF8NUL passwd 
         */

        challenge.len = s->qlogin.len + s->zlogin.len + 1 +
                        s->dusr.len + s->zusr.len + 1 +
                        s->dpasswd.len;
        line.len = ngx_base64_encoded_length (challenge.len);

        challenge.data = ngx_palloc (c->pool, challenge.len);
        if (challenge.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.data = ngx_palloc (c->pool, line.len + 2);   /* +2 for CRLF */
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        /* construct the base64 challenge for auth-plain login to upstream */

        p = challenge.data;
        p = ngx_cpymem(p, s->qlogin.data, s->qlogin.len);   /* authz */
        p = ngx_cpymem(p, s->zlogin.data, s->zlogin.len); /* [/wm|/ni|/tb] */
        *p++ = '\x0';
        p = ngx_cpymem(p, s->dusr.data, s->dusr.len);     /* authc */
        p = ngx_cpymem(p, s->zusr.data, s->zusr.len);     /* [/wm|/ni|/tb] for authc */
        *p++ = '\x0';
        p = ngx_cpymem(p, s->dpasswd.data, s->dpasswd.len); /* password */

        ngx_encode_base64 (&line, &challenge);

        if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, rev->log, 0,
                            "sending AUTH X-ZIMBRA challenge to upstream"
                           );
        }
        else {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, rev->log, 0,
                            "sending AUTH PLAIN challenge to upstream"
                           );
        }

        ngx_memcpy (line.data + line.len, CRLF, 2);
        line.len += 2;

        s->mail_state = ngx_imap_auth_plain_ir;

        break;

    default:
#if (NGX_SUPPRESS_WARN)
        line.len = 0;
        line.data = NULL;
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_mail_proxy_smtp_handler(ngx_event_t *rev)
{
    u_char                    *p;
    ngx_int_t                  rc;
    ngx_str_t                  line;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_proxy_conf_t     *pcf;
    ngx_mail_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy smtp auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    rc = ngx_mail_proxy_read_response(s, s->mail_state);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case ngx_smtp_start:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send ehlo");

        s->connection->log->action = "sending HELO/EHLO to upstream";

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        line.len = sizeof("HELO ")  - 1 + cscf->server_name.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

        p = ngx_cpymem(line.data,
                       ((s->esmtp || pcf->xclient) ? "EHLO " : "HELO "),
                       sizeof("HELO ") - 1);

        p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
        *p++ = CR; *p = LF;

        if (pcf->xclient) {
            s->mail_state = ngx_smtp_helo_xclient;

        } else if (s->auth_method == NGX_MAIL_AUTH_NONE) {
            s->mail_state = ngx_smtp_helo_from;

        } else {
            s->mail_state = ngx_smtp_helo;
        }

        break;

    case ngx_smtp_helo_xclient:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send xclient");

        s->connection->log->action = "sending XCLIENT to upstream";

        line.len = sizeof("XCLIENT ADDR= LOGIN= NAME="
                          CRLF) - 1
                   + s->connection->addr_text.len + s->login.len + s->host.len;

#if (NGX_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            line.len += sizeof("IPV6:") - 1;
        }
#endif

        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, "XCLIENT ADDR=", sizeof("XCLIENT ADDR=") - 1);

#if (NGX_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            p = ngx_cpymem(p, "IPV6:", sizeof("IPV6:") - 1);
        }
#endif

        p = ngx_copy(p, s->connection->addr_text.data,
                     s->connection->addr_text.len);

        if (s->login.len) {
            p = ngx_cpymem(p, " LOGIN=", sizeof(" LOGIN=") - 1);
            p = ngx_copy(p, s->login.data, s->login.len);
        }

        p = ngx_cpymem(p, " NAME=", sizeof(" NAME=") - 1);
        p = ngx_copy(p, s->host.data, s->host.len);

        *p++ = CR; *p++ = LF;

        line.len = p - line.data;

        if (s->smtp_helo.len) {
            s->mail_state = ngx_smtp_xclient_helo;

        } else if (s->auth_method == NGX_MAIL_AUTH_NONE) {
            s->mail_state = ngx_smtp_xclient_from;

        } else {
            s->mail_state = ngx_smtp_xclient;
        }

        break;

    case ngx_smtp_xclient_helo:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send client ehlo");

        s->connection->log->action = "sending client HELO/EHLO to upstream";

        line.len = sizeof("HELO " CRLF) - 1 + s->smtp_helo.len;

        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data,
                       ((s->esmtp) ? "EHLO %V" CRLF : "HELO %V" CRLF),
                       &s->smtp_helo)
                   - line.data;

        s->mail_state = (s->auth_method == NGX_MAIL_AUTH_NONE) ?
                            ngx_smtp_helo_from : ngx_smtp_helo;

        break;

    case ngx_smtp_helo_from:
    case ngx_smtp_xclient_from:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send mail from");

        s->connection->log->action = "sending MAIL FROM to upstream";

        line.len = s->smtp_from.len + sizeof(CRLF) - 1;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->smtp_from.data, s->smtp_from.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_smtp_from;

        break;

    case ngx_smtp_from:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send rcpt to");

        s->connection->log->action = "sending RCPT TO to upstream";

        line.len = s->smtp_to.len + sizeof(CRLF) - 1;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->smtp_to.data, s->smtp_to.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_smtp_to;

        break;

    case ngx_smtp_helo:
    case ngx_smtp_xclient:
    case ngx_smtp_to:

        b = s->proxy->buffer;

        if (s->auth_method == NGX_MAIL_AUTH_NONE) {
            b->pos = b->start;

        } else {
            ngx_memcpy(b->start, smtp_auth_ok, sizeof(smtp_auth_ok) - 1);
            b->last = b->start + sizeof(smtp_auth_ok) - 1;
        }

        s->connection->read->handler = ngx_mail_proxy_handler;
        s->connection->write->handler = ngx_mail_proxy_handler;
        rev->handler = ngx_mail_proxy_handler;
        c->write->handler = ngx_mail_proxy_handler;

        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

        if (s->buffer->pos == s->buffer->last) {
            ngx_mail_proxy_handler(s->connection->write);

        } else {
            ngx_mail_proxy_handler(c->write);
        }

        return;

    default:
#if (NGX_SUPPRESS_WARN)
        ngx_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_mail_proxy_dummy_handler(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy dummy handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        c = wev->data;
        s = c->data;

        ngx_mail_proxy_close_session(s);
    }
}


static ngx_int_t
ngx_mail_proxy_read_response(ngx_mail_session_t *s, ngx_uint_t state)
{
    u_char                 *p, *m;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_mail_proxy_conf_t  *pcf;
    int                     expect_chunk;

    /* (bug 21323)

       during the authentication phase, the upstream imap server can include an
       optional untagged response to the LOGIN or to the ID command
       if the `nio_imap_enabled' parameter is set to true, then the upstream 
       server's response is split into two tcp packets, the first chunk
       contains the untagged response, and the next chunk contains the tagged
       result

       in this function, nginx previously expected all the response to arrive
       in a single chunk, which is not true in this case, and therefore, we 
       must maintain a state variable (expect_chunk), which has boolean 
       significance -- if the variable starts off as false, and it is marked 
       true when we encounter an untagged response

       when the tagged response eventually arrives (the tag identifier is at 
       the start of a new line of response), then this variable is signaled
       to false again, which means that we don't expect another chunk of 
       data

       if we finish processing the data returned by the call to recv(), and
       if expect_chunk is set to true, then we return NGX_AGAIN, which will
       cause this handler to get invoked again, when the next chunk of data
       becomes available
     */

    s->connection->log->action = "reading response from upstream";

    b = s->proxy->buffer;

    n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
                                            b->last, b->end - b->last);

    if (n == NGX_ERROR || n == 0) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    b->last += n;

    /* if (b->last - b->pos < 5) {
        return NGX_AGAIN;
    } */ /* -- This won't work with zimbra */

    if ((b->last - b->pos < 5) && (b->pos) && (*b->pos != '+'))
    {
        return NGX_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    expect_chunk = 0;
    p = b->pos;

    switch (s->protocol) {

    case NGX_MAIL_POP3_PROTOCOL:
        if (state == ngx_pop3_auth_plain) {
            if (p[0] == '+' && p[1] == ' ') {
                return NGX_OK;
            }
        } else {
            if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
                return NGX_OK;
            }
        }
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        switch (state) {

        case ngx_imap_start:
            if (ngx_strncmp(p, "* OK", sizeof("* OK") - 1) == 0) {
                char *k = strchr((char *)p, '\n');
                if (k != NULL) {
                    /* bug 79531 identify the [ALERT] msg from upstream */
                    if (ngx_strncmp(k+1, "* OK [ALERT]", sizeof("* OK [ALERT]") - 1) == 0) {
                        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                                        "ALERT message recvd from upstream");
                        s->out.len = b->last - b->pos;
                        s->out.data = b->pos;
                        return NGX_ABORT;
                    }
                }
                return NGX_OK;
            }
            break;

        case ngx_imap_login:
        case ngx_imap_user:
        case ngx_imap_auth_plain:
            if (p[0] == '+') {
                return NGX_OK;
            }
            break;

        case ngx_imap_id:
            /* bug 68678 ignore the untagged error for the ID command */
            if (ngx_strncmp(p, "* BAD", sizeof("* BAD") - 1) == 0) {
                return NGX_OK;
            }

            /* fall through */
        case ngx_imap_passwd:
        case ngx_imap_auth_plain_ir:
            /* Consume (optional, untagged response, plus) tagged response to 
               IMAP command previously issued
               As the switch case indicates, we are prepared to handle this 
               after sending the ID command, or after sending the password to
               the upstream imap server
               In the former case, the IMAP server MAY optionally include an
               untagged ID repsonse (RFC 2971, section 3.1)
               In the latter case, the IMAP server MAY include a CAPABILITY
               response code in the tagged OK response to a successful LOGIN
               command (RFC 3501, section 6.2.3)
             */

            while ((p != NULL) && (p < b->last))
            {
                if (ngx_strncmp(p, s->tag.data, s->tag.len) == 0)
                {
                    /* This line is the tagged response */
                    expect_chunk = 0;

                    p += s->tag.len + 1 /*for space*/;
                    if (p[0] == 'O' && p[1] == 'K')
                    {
                        return NGX_OK;
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    /* this line is any optional untagged response 
                     */
                    p = (u_char *)strstr ((char *)p, (char *)"\n");
                    if (!p)
                    {
                        /* if we don't find the newline, it indicates an
                           invalid response
                         */
                        break;
                    }
                    else
                    {
                        /* the first (possible) chunk has been read */
                        expect_chunk = 1;
                        ++p;
                    }
                }
            }
            break;
        }

        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */

        if (p[3] == '-') {
            /* multiline reply, check if we got last line */

            m = b->last - (sizeof(CRLF "200" CRLF) - 1);

            while (m > p) {
                if (m[0] == CR && m[1] == LF) {
                    break;
                }

                m--;
            }

            if (m <= p || m[5] == '-') {
                return NGX_AGAIN;
            }
        }

        switch (state) {

        case ngx_smtp_start:
            if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
                return NGX_OK;
            }
            break;

        case ngx_smtp_helo:
        case ngx_smtp_helo_xclient:
        case ngx_smtp_helo_from:
        case ngx_smtp_from:
            if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
                return NGX_OK;
            }
            break;

        case ngx_smtp_xclient:
        case ngx_smtp_xclient_from:
        case ngx_smtp_xclient_helo:
            if (p[0] == '2' && (p[1] == '2' || p[1] == '5') && p[2] == '0') {
                return NGX_OK;
            }
            break;

        case ngx_smtp_to:
            return NGX_OK;
        }

        break;
    }

    if (expect_chunk == 1) {
        return NGX_AGAIN;
    }

    s->sendquitmsg = 1;
    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

    if (pcf->pass_error_message == 0) {
        *(b->last - 2) = '\0';
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid response: \"%s\"", p);
        return NGX_ERROR;
    }

    s->out.len = b->last - p - 2;
    s->out.data = p;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "upstream sent invalid response: \"%V\"", &s->out);

    s->out.len = b->last - b->pos;
    s->out.data = b->pos;

    return NGX_ERROR;
}


static void
ngx_mail_proxy_handler(ngx_event_t *ev)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_uint_t              do_write;
    ngx_connection_t       *c, *src, *dst;
    ngx_mail_session_t     *s;
    ngx_mail_proxy_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    if (ev->timedout || c->close) {
        c->log->action = "proxying";

        if (c->close) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");

        } else if (c == s->connection) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

        s->sendquitmsg = 1;
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        if (ev->write) {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = s->proxy->upstream.connection;
            dst = c;
            b = s->proxy->buffer;

        } else {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = c;
            dst = s->proxy->upstream.connection;
            b = s->buffer;
        }

    } else {
        if (ev->write) {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;

        } else {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = c;
            dst = s->connection;
            b = s->proxy->buffer;
        }
    }

    do_write = ev->write ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail proxy handler: %ui, #%d > #%d",
                   do_write, src->fd, dst->fd);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_mail_proxy_close_session(s);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                if (c == s->connection && !ev->write) {
                    s->sendquitmsg = 1;
                }
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
        || (s->proxy->upstream.connection->read->eof
            && s->proxy->buffer->pos == s->proxy->buffer->last)
        || (s->connection->read->eof
            && s->proxy->upstream.connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
        ngx_add_timer(c->read, pcf->timeout);
    }
}


/* error out of an established proxy session
    - close the upstream connection
    - close the downstream connection after sending any pending data
 */
static void
ngx_mail_proxy_upstream_error(ngx_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

#if (NGX_MAIL_SSL)

        if (s->proxy->upstream.connection->ssl) {
            s->proxy->upstream.connection->ssl->no_wait_shutdown = 1;
            ngx_ssl_shutdown(s->proxy->upstream.connection);
        }
#endif

        ngx_close_connection(s->proxy->upstream.connection);
    }

    if (s->out.len == 0) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->quit = 1;
    ngx_mail_send(s->connection->write);
}


static void
ngx_mail_proxy_internal_server_error(ngx_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

#if (NGX_MAIL_SSL)

        if (s->proxy->upstream.connection->ssl) {
            s->proxy->upstream.connection->ssl->no_wait_shutdown = 1;
            ngx_ssl_shutdown(s->proxy->upstream.connection);
        }
#endif

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_mail_session_internal_server_error(s);
}


static void
ngx_mail_proxy_close_session(ngx_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

#if (NGX_MAIL_SSL)

        if (s->proxy->upstream.connection->ssl) {
            s->proxy->upstream.connection->ssl->no_wait_shutdown = 1;
            ngx_ssl_shutdown(s->proxy->upstream.connection);
        }
#endif

        ngx_close_connection(s->proxy->upstream.connection);
    }

    if (s->sendquitmsg) {
        ngx_mail_end_session(s);
    } else {
        ngx_mail_close_connection(s->connection);
    }
}


static void *
ngx_mail_proxy_create_conf(ngx_conf_t *cf)
{
    ngx_mail_proxy_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->enable = NGX_CONF_UNSET;
    pcf->pass_error_message = NGX_CONF_UNSET;
    pcf->issue_pop3_xoip = NGX_CONF_UNSET;
    pcf->issue_imap_id = NGX_CONF_UNSET;
    pcf->xclient = NGX_CONF_UNSET;
    pcf->buffer_size = NGX_CONF_UNSET_SIZE;
    pcf->ctimeout = NGX_CONF_UNSET_MSEC;
    pcf->timeout = NGX_CONF_UNSET_MSEC;
    pcf->proxy_ssl = NGX_CONF_UNSET;
    pcf->ssl = NGX_CONF_UNSET_PTR;

    return pcf;
}


static char *
ngx_mail_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_proxy_conf_t *prev = parent;
    ngx_mail_proxy_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
    ngx_conf_merge_value(conf->issue_pop3_xoip, prev->issue_pop3_xoip, 1);
    ngx_conf_merge_value(conf->issue_imap_id, prev->issue_imap_id, 1);
    ngx_conf_merge_value(conf->xclient, prev->xclient, 1);
    ngx_conf_merge_value(conf->proxy_ssl, prev->proxy_ssl, 0);
    ngx_conf_merge_ptr_value(conf->ssl, prev->ssl, NULL);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->ctimeout, prev->ctimeout, 2 * 60000);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return NGX_CONF_OK;
}

#if (NGX_MAIL_SSL)

static char *
ngx_mail_proxy_ssl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_pool_cleanup_t    *cln;
    char                  *rc;
    ngx_mail_proxy_conf_t *pcf;

    rc = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    pcf = (ngx_mail_proxy_conf_t *)conf;

    if (!pcf->proxy_ssl) {
        return NGX_CONF_OK;
    }

    pcf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));

    if (pcf->ssl == NULL) {
        return NGX_CONF_ERROR;
    }

    pcf->ssl->log = cf->log;

    // don't support SSLv2 anymore
    if (ngx_ssl_create(pcf->ssl, ~(NGX_SSL_SSLv2|NGX_SSL_SSLv3), NULL)
            != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = pcf->ssl;

    return NGX_CONF_OK;
}

#endif
/* throttle imap session if necessary (user has just finished logging in) */
static void ngx_mail_proxy_throttle_imap(ngx_event_t *rev)
{
    throttle_callback_t          *callback;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_mail_proxy_conf_t        *pcf;
    ngx_mail_session_t           *s;
    ngx_connection_t             *c;
    ngx_pool_t                   *pool;
    ngx_log_t                    *log;
    ngx_str_t                     user;

    c = rev->data;
    s = c->data;
    pool = c->pool;
    log = ngx_cycle->log;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

    callback = ngx_pcalloc(pool, sizeof(throttle_callback_t));
    if (callback == NULL) {
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    callback->check_only = 0;    /* increment the counter */
    callback->session = s;
    callback->connection = c;
    callback->rev = rev;
    callback->config = pcf;
    callback->log = log;
    callback->pool = pool;
    callback->on_allow = ngx_mail_proxy_allow_imap;
    callback->on_deny = ngx_mail_proxy_choke_imap;

    if (tscf->mail_login_user_max == 0) {
        callback->on_allow(callback);
    } else {
        user = s->qlogin;
        if ((user.len == 0) && (s->auth_method == NGX_MAIL_AUTH_PLAIN
                || s->auth_method == NGX_MAIL_AUTH_PLAIN_IR)) {
            user = s->dusr;
        }
        ngx_mail_throttle_user(user, callback);
    }
}

static void ngx_mail_proxy_allow_imap(throttle_callback_t *callback)
{
    ngx_mail_session_t      *s = callback->session;
    ngx_event_t             *rev = callback->rev;
    ngx_connection_t        *c = callback->connection;
    ngx_mail_proxy_conf_t   *pcf = callback->config;

    s->connection->read->handler = ngx_mail_proxy_handler;
    s->connection->write->handler = ngx_mail_proxy_handler;
    rev->handler = ngx_mail_proxy_handler;
    c->write->handler = ngx_mail_proxy_handler;

    ngx_add_timer(s->connection->read, pcf->timeout);
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->log->action = NULL;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

    ngx_mail_proxy_handler(s->connection->write);
}

static void ngx_mail_proxy_choke_imap(throttle_callback_t *callback)
{
    ngx_mail_session_t  *s = callback->session;
    ngx_mail_proxy_choke_session(s);
}

/* throttle pop3 session if necessary (user has just finished logging in) */
static void ngx_mail_proxy_throttle_pop3(ngx_event_t *rev)
{
    throttle_callback_t          *callback;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_mail_proxy_conf_t        *pcf;
    ngx_mail_session_t           *s;
    ngx_connection_t             *c;
    ngx_pool_t                   *pool;
    ngx_log_t                    *log;
    ngx_str_t                     user;

    c = rev->data;
    s = c->data;
    pool = c->pool;
    log = ngx_cycle->log;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

    callback = ngx_pcalloc(pool, sizeof(throttle_callback_t));
    if (callback == NULL) {
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    callback->check_only = 0;    /* increment the counter */
    callback->session = s;
    callback->connection = c;
    callback->rev = rev;
    callback->config = pcf;
    callback->log = log;
    callback->pool = pool;
    callback->on_allow = ngx_mail_proxy_allow_pop3;
    callback->on_deny = ngx_mail_proxy_choke_pop3;

    if (tscf->mail_login_user_max == 0) {
        callback->on_allow(callback);
    } else {
        user = s->qlogin;
        if ((user.len == 0) && (s->auth_method == NGX_MAIL_AUTH_PLAIN
                || s->auth_method == NGX_MAIL_AUTH_PLAIN_IR)) {
            user = s->dusr;
        }
        ngx_mail_throttle_user(user, callback);
    }
}

static void ngx_mail_proxy_allow_pop3(throttle_callback_t *callback)
{
    ngx_mail_session_t      *s = callback->session;
    ngx_event_t             *rev = callback->rev;
    ngx_connection_t        *c = callback->connection;
    ngx_mail_proxy_conf_t   *pcf = callback->config;

    s->connection->read->handler = ngx_mail_proxy_handler;
    s->connection->write->handler = ngx_mail_proxy_handler;
    rev->handler = ngx_mail_proxy_handler;
    c->write->handler = ngx_mail_proxy_handler;

    ngx_add_timer(s->connection->read, pcf->timeout);
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->log->action = NULL;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

    ngx_mail_proxy_handler(s->connection->write);
}

static void ngx_mail_proxy_choke_pop3(throttle_callback_t *callback)
{
    ngx_mail_session_t  *s = callback->session;
    ngx_mail_proxy_choke_session(s);
}

static void ngx_mail_proxy_choke_session(ngx_mail_session_t *s)
{
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_str_t                     bye, msg, umsg;
    ngx_pool_t                   *pool;
    u_char                       *p;

    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    pool = s->connection->pool;
    msg = tscf->mail_login_user_rejectmsg;

    if (s->proxy->upstream.connection)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

#if (NGX_MAIL_SSL)

        if (s->proxy->upstream.connection->ssl) {
            s->proxy->upstream.connection->ssl->no_wait_shutdown = 1;
            ngx_ssl_shutdown(s->proxy->upstream.connection);
        }
#endif

        ngx_close_connection(s->proxy->upstream.connection);
    }

    if (s->protocol == NGX_MAIL_IMAP_PROTOCOL)
    {
        bye.len =   sizeof("* BYE ") - 1 +
                    msg.len +
                    sizeof(CRLF) - 1;

        bye.data = ngx_palloc(pool, bye.len);

        if (bye.data != NULL)
        {
            p = bye.data;
            p = ngx_cpymem(p,"* BYE ",sizeof("* BYE ")-1);
            p = ngx_cpymem(p, msg.data, msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p - bye.data;
        }
        else
        {
            bye.data = (u_char *) ("* BYE" CRLF);
            bye.len = sizeof("* BYE" CRLF)-1;
        }

        s->out = bye;
        s->quit = 0;
        ngx_mail_send(s->connection->write);

        if (s->command == NGX_IMAP_LOGIN) {
            umsg.data = imap_login_no;
            umsg.len = sizeof(imap_login_no) - 1;
        } else if (s->command == NGX_IMAP_AUTHENTICATE) {
            umsg.data = imap_auth_no;
            umsg.len = sizeof(imap_auth_no) - 1;
        } else {
            umsg.data = imap_no;
            umsg.len = sizeof(imap_no) - 1;
        }

        s->out.len = s->tag.len + 1 /*for space*/+ umsg.len;
        s->out.data = ngx_palloc(pool, s->out.len);

        if (s->out.data == NULL) {
            s->out.data = (u_char*)"";
            s->out.len = 0;
            ngx_mail_close_connection(s->connection);
        } else {
            ngx_memcpy(s->out.data, s->tag.data, s->tag.len);
            *(s->out.data + s->tag.len) = ' ';
            ngx_memcpy(s->out.data + s->tag.len + 1, umsg.data, umsg.len);
            s->quit = 1;
            ngx_mail_send(s->connection->write);
        }

        return;
    }
    else if (s->protocol == NGX_MAIL_POP3_PROTOCOL)
    {
        bye.len = sizeof("-ERR ")-1 +
                  msg.len +
                  sizeof(CRLF)-1;

        bye.data = ngx_palloc(pool,bye.len);

        if (bye.data != NULL)
        {
            p = bye.data;
            p = ngx_cpymem(p,"-ERR ",sizeof("-ERR ")-1);
            p = ngx_cpymem(p,msg.data,msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p-bye.data;
        }
        else
        {
            bye.data = (u_char *)("-ERR" CRLF);
            bye.len = sizeof("-ERR" CRLF)-1;
        }

        s->out = bye;
        s->quit = 1;
        ngx_mail_send(s->connection->write);
        return;
    }
    else
    {
        /* TODO ?? reject SMTP ?? */
        bye.data = (u_char *)"";
        bye.len = 0;
        s->out = bye;
        s->quit = 1;
        ngx_mail_send(s->connection->write);
        return;
    }
}

/* Quote an IMAP string according to RFC 3501, section 9 (formal syntax) */
static ngx_str_t ngx_imap_quote_string(ngx_pool_t *pool, ngx_str_t *u)
{
    size_t      s;
    ngx_str_t   k;
    u_char     *p,*q,*r;

    s = 2;
    q = u->data;
    r = q + u->len;

    while (q<r) {
        if (*q == '"' || *q == '\\') { ++s; }
        ++s;
        ++q;
    }

    k.data = ngx_palloc(pool,s);
    if (k.data == NULL) {
        k = *u;
    } else {
        k.len = s;
        p = k.data;
        q = u->data;
        r = q + u->len;
        *p++ = '"';
        while (q<r) {
            if (*q == '"' || *q == '\\') { *p++ = '\\'; }
            *p++ = *q++;
        }
        *p++ = '"';
    }

    return k;
}

static void
ngx_mail_proxy_auth_sleep_handler (ngx_event_t *rev)
{
    ngx_connection_t        *c;
    ngx_mail_session_t      *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
        "mail proxy auth sleep handler");

    c = rev->data;
    s = c->data;

    ngx_zm_lookup_delete_cache(s->key_alias, s->key_route);

    if (rev->timedout) {
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    if (rev->active) {
        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_mail_proxy_upstream_error(s);
        }
    }
}

ngx_flag_t
ngx_mail_get_proxy_ssl (ngx_mail_session_t * s)
{
    ngx_mail_proxy_conf_t * pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
    return pcf->proxy_ssl;
}

#if (NGX_HTTP_SSL)

static void
ngx_mail_proxy_ssl_init_connection(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t               rc;
    ngx_mail_proxy_conf_t  *pcf;

    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

    if (ngx_ssl_create_connection(pcf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        c->ssl->handler = ngx_mail_proxy_ssl_handshake;
        return;
    }

    ngx_mail_proxy_ssl_handshake(c);
}


static void
ngx_mail_proxy_ssl_handshake(ngx_connection_t *c)
{
    ngx_mail_session_t  *s;
    s = c->data;

    if (c->ssl->handshaked) {

        c->write->handler = ngx_mail_proxy_dummy_handler;
        switch (s->protocol) {

            case NGX_MAIL_POP3_PROTOCOL:
                c->read->handler = ngx_mail_proxy_pop3_handler;
                s->mail_state = ngx_pop3_start;
                break;

            case NGX_MAIL_IMAP_PROTOCOL:
                c->read->handler = ngx_mail_proxy_imap_handler;
                s->mail_state = ngx_imap_start;
                break;

            default: /* NGX_MAIL_SMTP_PROTOCOL */
                c->read->handler = ngx_mail_proxy_smtp_handler;
                s->mail_state = ngx_smtp_start;
                break;
        }

        /* server might have send the intial welcome msg */
        c->read->handler(c->read);
    } else {
        /* when handshake fails, we should close the session */
        ngx_mail_proxy_upstream_error(s);
    }
}

/** TODO support ssl session reuse
void
ngx_mail_proxy_set_session (ngx_peer_connection_t *pc, ngx_mail_proxy_ctx_t *ctx)
{
    ngx_ssl_session_t   *ssl_session;
    ngx_int_t            rc;

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, pc->log, 0,
                   "set session: %p:%d",
                   ssl_session, ssl_session ? ssl_session->references : 0);
    return;
}

void
ngx_mail_proxy_save_session (ngx_peer_connection_t *pc)
{

}
*/

#endif

