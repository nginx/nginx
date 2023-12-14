
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>


static void ngx_stream_log_session(ngx_stream_session_t *s);
static void ngx_stream_close_connection(ngx_connection_t *c);
static u_char *ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len);
static void ngx_stream_proxy_protocol_handler(ngx_event_t *rev);


void
ngx_stream_init_connection(ngx_connection_t *c)
{
    u_char                        text[NGX_SOCKADDR_STRLEN];
    size_t                        len;
    ngx_uint_t                    i;
    ngx_time_t                   *tp;
    ngx_event_t                  *rev;
    struct sockaddr              *sa;
    ngx_stream_port_t            *port;
    struct sockaddr_in           *sin;
    ngx_stream_in_addr_t         *addr;
    ngx_stream_session_t         *s;
    ngx_stream_conf_ctx_t        *ctx;
    ngx_stream_addr_conf_t       *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    ngx_stream_in6_addr_t        *addr6;
#endif
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_core_main_conf_t  *cmcf;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() and recvmsg() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_stream_close_connection(c);
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

    s = ngx_pcalloc(c->pool, sizeof(ngx_stream_session_t));
    if (s == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    ctx = addr_conf->default_server->ctx;

    s->signature = NGX_STREAM_MODULE;
    s->main_conf = ctx->main_conf;
    s->srv_conf = ctx->srv_conf;
    s->virtual_names = addr_conf->virtual_names;

#if (NGX_STREAM_SSL)
    s->ssl = addr_conf->ssl;
#endif

    if (c->buffer) {
        s->received += c->buffer->last - c->buffer->pos;
    }

    s->connection = c;
    c->data = s;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    ngx_set_connection_log(c, cscf->error_log);

    len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
                  c->number, c->type == SOCK_DGRAM ? "udp " : "",
                  len, text, &c->listening->addr_text);

    c->log->connection = c->number;
    c->log->handler = ngx_stream_log_error;
    c->log->data = s;
    c->log->action = "initializing session";
    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_stream_max_module);
    if (s->ctx == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    s->variables = ngx_pcalloc(s->connection->pool,
                               cmcf->variables.nelts
                               * sizeof(ngx_stream_variable_value_t));

    if (s->variables == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    rev = c->read;
    rev->handler = ngx_stream_session_handler;

    if (addr_conf->proxy_protocol) {
        c->log->action = "reading PROXY protocol";

        rev->handler = ngx_stream_proxy_protocol_handler;

        if (!rev->ready) {
            ngx_add_timer(rev, cscf->proxy_protocol_timeout);

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s,
                                            NGX_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    if (ngx_use_accept_mutex) {
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    rev->handler(rev);
}


static void
ngx_stream_proxy_protocol_handler(ngx_event_t *rev)
{
    u_char                      *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER];
    size_t                       size;
    ssize_t                      n;
    ngx_err_t                    err;
    ngx_connection_t            *c;
    ngx_stream_session_t        *s;
    ngx_stream_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream PROXY protocol handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = ngx_stream_get_module_srv_conf(s,
                                                      ngx_stream_core_module);

                ngx_add_timer(rev, cscf->proxy_protocol_timeout);
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s,
                                            NGX_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }

        ngx_connection_error(c, err, "recv() failed");

        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    p = ngx_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->log->action = "initializing session";

    ngx_stream_session_handler(rev);
}


void
ngx_stream_session_handler(ngx_event_t *rev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_stream_core_run_phases(s);
}


void
ngx_stream_finalize_session(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream session: %i", rc);

    s->status = rc;

    ngx_stream_log_session(s);

    ngx_stream_close_connection(s->connection);
}


static void
ngx_stream_log_session(ngx_stream_session_t *s)
{
    ngx_uint_t                    i, n;
    ngx_stream_handler_pt        *log_handler;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    log_handler = cmcf->phases[NGX_STREAM_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_STREAM_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}


static void
ngx_stream_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (NGX_STREAM_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_stream_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static u_char *
ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    ngx_stream_session_t  *s;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = ngx_snprintf(buf, len, ", %sclient: %V, server: %V",
                     s->connection->type == SOCK_DGRAM ? "udp " : "",
                     &s->connection->addr_text,
                     &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->log_handler) {
        p = s->log_handler(log, buf, len);
    }

    return p;
}
