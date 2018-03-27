
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PP_V2_SIGLEN         12
#define NGX_PP_V2_CMD_PROXY      1
#define NGX_PP_V2_STREAM         1

#define NGX_PP_V2_AF_UNSPEC      0
#define NGX_PP_V2_AF_INET        1
#define NGX_PP_V2_AF_INET6       2


#define ngx_pp_v2_get_u16(p)     ((p)[0] << 8 | (p)[1])


typedef struct {
    u_char                       signature[NGX_PP_V2_SIGLEN];
    u_char                       ver_cmd;
    u_char                       family_transport;
    u_char                       len[2];
} ngx_pp_v2_header_t;


typedef struct {
    u_char                       src[4];
    u_char                       dst[4];
    u_char                       sport[2];
    u_char                       dport[2];
} ngx_pp_v2_inet_addrs_t;


typedef struct {
    u_char                       src[16];
    u_char                       dst[16];
    u_char                       sport[2];
    u_char                       dport[2];
} ngx_pp_v2_inet6_addrs_t;


typedef union {
    ngx_pp_v2_inet_addrs_t       inet;
    ngx_pp_v2_inet6_addrs_t      inet6;
} ngx_pp_v2_addrs_t;


static u_char *ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf,
    u_char *last);

static const u_char ngx_pp_v2_signature[NGX_PP_V2_SIGLEN] =
    { 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a };


u_char *
ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    size_t     len;
    u_char     ch, *p, *addr, *port;
    ngx_int_t  n;

    p = buf;
    len = last - buf;

    if (len >= sizeof(ngx_pp_v2_header_t)
        && memcmp(p, ngx_pp_v2_signature, NGX_PP_V2_SIGLEN) == 0)
    {
        return ngx_proxy_protocol_v2_read(c, buf, last);
    }

    if (len < 8 || ngx_strncmp(p, "PROXY ", 6) != 0) {
        goto invalid;
    }

    p += 6;
    len -= 6;

    if (len >= 7 && ngx_strncmp(p, "UNKNOWN", 7) == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol unknown protocol");
        p += 7;
        goto skip;
    }

    if (len < 5 || ngx_strncmp(p, "TCP", 3) != 0
        || (p[3] != '4' && p[3] != '6') || p[4] != ' ')
    {
        goto invalid;
    }

    p += 5;
    addr = p;

    for ( ;; ) {
        if (p == last) {
            goto invalid;
        }

        ch = *p++;

        if (ch == ' ') {
            break;
        }

        if (ch != ':' && ch != '.'
            && (ch < 'a' || ch > 'f')
            && (ch < 'A' || ch > 'F')
            && (ch < '0' || ch > '9'))
        {
            goto invalid;
        }
    }

    len = p - addr - 1;
    c->proxy_protocol_addr.data = ngx_pnalloc(c->pool, len);

    if (c->proxy_protocol_addr.data == NULL) {
        return NULL;
    }

    ngx_memcpy(c->proxy_protocol_addr.data, addr, len);
    c->proxy_protocol_addr.len = len;

    for ( ;; ) {
        if (p == last) {
            goto invalid;
        }

        if (*p++ == ' ') {
            break;
        }
    }

    port = p;

    for ( ;; ) {
        if (p == last) {
            goto invalid;
        }

        if (*p++ == ' ') {
            break;
        }
    }

    len = p - port - 1;

    n = ngx_atoi(port, len);

    if (n < 0 || n > 65535) {
        goto invalid;
    }

    c->proxy_protocol_port = (in_port_t) n;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol address: %V %d", &c->proxy_protocol_addr,
                   c->proxy_protocol_port);

skip:

    for ( /* void */ ; p < last - 1; p++) {
        if (p[0] == CR && p[1] == LF) {
            return p + 2;
        }
    }

invalid:

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "broken header: \"%*s\"", (size_t) (last - buf), buf);

    return NULL;
}


u_char *
ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last)
{
    ngx_uint_t  port, lport;

    if (last - buf < NGX_PROXY_PROTOCOL_MAX_HEADER) {
        return NULL;
    }

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NULL;
    }

    switch (c->sockaddr->sa_family) {

    case AF_INET:
        buf = ngx_cpymem(buf, "PROXY TCP4 ", sizeof("PROXY TCP4 ") - 1);
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        buf = ngx_cpymem(buf, "PROXY TCP6 ", sizeof("PROXY TCP6 ") - 1);
        break;
#endif

    default:
        return ngx_cpymem(buf, "PROXY UNKNOWN" CRLF,
                          sizeof("PROXY UNKNOWN" CRLF) - 1);
    }

    buf += ngx_sock_ntop(c->sockaddr, c->socklen, buf, last - buf, 0);

    *buf++ = ' ';

    buf += ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf, last - buf,
                         0);

    port = ngx_inet_get_port(c->sockaddr);
    lport = ngx_inet_get_port(c->local_sockaddr);

    return ngx_slprintf(buf, last, " %ui %ui" CRLF, port, lport);
}


static u_char *
ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    u_char              *end;
    size_t               len;
    socklen_t            socklen;
    ngx_str_t           *name;
    ngx_uint_t           ver, cmd, family, transport;
    ngx_sockaddr_t       sockaddr;
    ngx_pp_v2_addrs_t   *addrs;
    ngx_pp_v2_header_t  *hdr;

    hdr = (ngx_pp_v2_header_t *) buf;

    buf += sizeof(ngx_pp_v2_header_t);

    ver = hdr->ver_cmd >> 4;

    if (ver != 2) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "unsupported PROXY protocol version: %ui", ver);
        return NULL;
    }

    len = ngx_pp_v2_get_u16(hdr->len);

    if ((size_t) (last - buf) < len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "header is too large");
        return NULL;
    }

    end = buf + len;

    cmd = hdr->ver_cmd & 0x0f;

    if (cmd != NGX_PP_V2_CMD_PROXY) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported command 0x%xi", cmd);
        return end;
    }

    transport = hdr->family_transport & 0x0f;

    if (transport != NGX_PP_V2_STREAM) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported transport 0x%xi",
                       transport);
        return end;
    }

    family = hdr->family_transport >> 4;

    addrs = (ngx_pp_v2_addrs_t *) buf;

    switch (family) {

    case NGX_PP_V2_AF_UNSPEC:
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 AF_UNSPEC ignored");
        return end;

    case NGX_PP_V2_AF_INET:

        if ((size_t) (end - buf) < sizeof(ngx_pp_v2_inet_addrs_t)) {
            return NULL;
        }

        sockaddr.sockaddr_in.sin_family = AF_INET;
        sockaddr.sockaddr_in.sin_port = 0;
        memcpy(&sockaddr.sockaddr_in.sin_addr, addrs->inet.src, 4);

        c->proxy_protocol_port = ngx_pp_v2_get_u16(addrs->inet.sport);

        socklen = sizeof(struct sockaddr_in);

        buf += sizeof(ngx_pp_v2_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)

    case NGX_PP_V2_AF_INET6:

        if ((size_t) (end - buf) < sizeof(ngx_pp_v2_inet6_addrs_t)) {
            return NULL;
        }

        sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        sockaddr.sockaddr_in6.sin6_port = 0;
        memcpy(&sockaddr.sockaddr_in6.sin6_addr, addrs->inet6.src, 16);

        c->proxy_protocol_port = ngx_pp_v2_get_u16(addrs->inet6.sport);

        socklen = sizeof(struct sockaddr_in6);

        buf += sizeof(ngx_pp_v2_inet6_addrs_t);

        break;

#endif

    default:

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported address family 0x%xi",
                       family);
        return end;
    }

    name = &c->proxy_protocol_addr;

    name->data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (name->data == NULL) {
        return NULL;
    }

    name->len = ngx_sock_ntop(&sockaddr.sockaddr, socklen, name->data,
                              NGX_SOCKADDR_STRLEN, 0);
    if (name->len == 0) {
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 address: %V %d", name,
                   c->proxy_protocol_port);

    if (buf < end) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 %z bytes tlv ignored", end - buf);
    }

    return end;
}
