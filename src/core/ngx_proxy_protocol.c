
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define ngx_proxy_protocol_parse_uint16(p)                                    \
    ( ((uint16_t) (p)[0] << 8)                                                \
    + (           (p)[1]) )

#define ngx_proxy_protocol_parse_uint32(p)                                    \
    ( ((uint32_t) (p)[0] << 24)                                               \
    + (           (p)[1] << 16)                                               \
    + (           (p)[2] << 8)                                                \
    + (           (p)[3]) )


typedef struct {
    u_char                                  signature[12];
    u_char                                  version_command;
    u_char                                  family_transport;
    u_char                                  len[2];
} ngx_proxy_protocol_header_t;


typedef struct {
    u_char                                  src_addr[4];
    u_char                                  dst_addr[4];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} ngx_proxy_protocol_inet_addrs_t;


typedef struct {
    u_char                                  src_addr[16];
    u_char                                  dst_addr[16];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} ngx_proxy_protocol_inet6_addrs_t;


#if (NGX_HAVE_UNIX_DOMAIN)

typedef struct {
    u_char                                  src_addr[108];
    u_char                                  dst_addr[108];
} ngx_proxy_protocol_unix_addrs_t;

#endif


typedef struct {
    u_char                                  type;
    u_char                                  len[2];
} ngx_proxy_protocol_tlv_t;


typedef struct {
    u_char                                  client;
    u_char                                  verify[4];
} ngx_proxy_protocol_tlv_ssl_t;


typedef struct {
    ngx_str_t                               name;
    ngx_uint_t                              type;
} ngx_proxy_protocol_tlv_entry_t;


static u_char *ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p,
    u_char *last, ngx_str_t *addr);
static u_char *ngx_proxy_protocol_read_port(u_char *p, u_char *last,
    in_port_t *port, u_char sep);
static u_char *ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
static ngx_int_t ngx_proxy_protocol_lookup_tlv(ngx_connection_t *c,
    ngx_str_t *tlvs, ngx_uint_t type, ngx_str_t *value);


typedef struct {
    ngx_str_t   name;
    ngx_uint_t  type;
    ngx_uint_t  is_ssl_sub;
    ngx_uint_t  is_ssl_verify;
    ngx_uint_t  is_ssl_raw;
} ngx_proxy_protocol_tlv_name_t;


static ngx_proxy_protocol_tlv_name_t  ngx_proxy_protocol_tlv_names[] = {
    { ngx_string("alpn"),        NGX_PROXY_PROTOCOL_V2_TYPE_ALPN,           0, 0, 0 },
    { ngx_string("authority"),   NGX_PROXY_PROTOCOL_V2_TYPE_AUTHORITY,      0, 0, 0 },
    { ngx_string("unique_id"),   NGX_PROXY_PROTOCOL_V2_TYPE_UNIQUE_ID,      0, 0, 0 },
    { ngx_string("ssl"),         NGX_PROXY_PROTOCOL_V2_TYPE_SSL,            0, 0, 1 },
    { ngx_string("ssl_verify"),  0,                                         0, 1, 0 },
    { ngx_string("ssl_version"), NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_VERSION, 1, 0, 0 },
    { ngx_string("ssl_cn"),      NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CN,      1, 0, 0 },
    { ngx_string("ssl_cipher"),  NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CIPHER,  1, 0, 0 },
    { ngx_string("ssl_sig_alg"), NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_SIG_ALG, 1, 0, 0 },
    { ngx_string("ssl_key_alg"), NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_KEY_ALG, 1, 0, 0 },
    { ngx_string("netns"),       NGX_PROXY_PROTOCOL_V2_TYPE_NETNS,          0, 0, 0 },
    { ngx_null_string,           0,                                         0, 0, 0 }
};


u_char *
ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    size_t                 len;
    u_char                *p;
    ngx_proxy_protocol_t  *pp;

    static const u_char signature[] = "\r\n\r\n\0\r\nQUIT\n";

    p = buf;
    len = last - buf;

    if (len >= sizeof(ngx_proxy_protocol_header_t)
        && ngx_memcmp(p, signature, sizeof(signature) - 1) == 0)
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

    pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    p = ngx_proxy_protocol_read_addr(c, p, last, &pp->src_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_addr(c, p, last, &pp->dst_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_port(p, last, &pp->src_port, ' ');
    if (p == NULL) {
        goto invalid;
    }

    p = ngx_proxy_protocol_read_port(p, last, &pp->dst_port, CR);
    if (p == NULL) {
        goto invalid;
    }

    if (p == last) {
        goto invalid;
    }

    if (*p++ != LF) {
        goto invalid;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    c->proxy_protocol = pp;

    return p;

skip:

    for ( /* void */ ; p < last - 1; p++) {
        if (p[0] == CR && p[1] == LF) {
            return p + 2;
        }
    }

invalid:

    for (p = buf; p < last; p++) {
        if (*p == CR || *p == LF) {
            break;
        }
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "broken header: \"%*s\"", (size_t) (p - buf), buf);

    return NULL;
}


static u_char *
ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p, u_char *last,
    ngx_str_t *addr)
{
    size_t  len;
    u_char  ch, *pos;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
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
            return NULL;
        }
    }

    len = p - pos - 1;

    addr->data = ngx_pnalloc(c->pool, len);
    if (addr->data == NULL) {
        return NULL;
    }

    ngx_memcpy(addr->data, pos, len);
    addr->len = len;

    return p;
}


static u_char *
ngx_proxy_protocol_read_port(u_char *p, u_char *last, in_port_t *port,
    u_char sep)
{
    size_t      len;
    u_char     *pos;
    ngx_int_t   n;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
        }

        if (*p++ == sep) {
            break;
        }
    }

    len = p - pos - 1;

    n = ngx_atoi(pos, len);
    if (n < 0 || n > 65535) {
        return NULL;
    }

    *port = (in_port_t) n;

    return p;
}


u_char *
ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last)
{
    ngx_uint_t  port, lport;

    if (last - buf < NGX_PROXY_PROTOCOL_V1_MAX_HEADER) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "too small buffer for PROXY protocol");
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


u_char *
ngx_proxy_protocol_v2_write(ngx_connection_t *c, u_char *buf, u_char *last)
{
    u_char                             *p;
    u_char                              transport;
    ngx_uint_t                          port, lport;
    ngx_proxy_protocol_header_t        *header;
    ngx_proxy_protocol_inet_addrs_t    *in;
#if (NGX_HAVE_INET6)
    struct in6_addr                    *src6, *dst6;
    ngx_proxy_protocol_inet6_addrs_t   *in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    size_t                              path_len;
    ngx_proxy_protocol_unix_addrs_t    *un;
#endif

    static const u_char  signature[] = "\r\n\r\n\0\r\nQUIT\n";

    if (last - buf < NGX_PROXY_PROTOCOL_V2_MAX_HEADER) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "too small buffer for PROXY protocol v2");
        return NULL;
    }

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NULL;
    }

    header = (ngx_proxy_protocol_header_t *) buf;

    ngx_memcpy(header->signature, signature, sizeof(signature) - 1);

    header->version_command = 0x21;  /* version 2, PROXY command */

    transport = (c->type == SOCK_DGRAM) ? 0x02 : 0x01;

    p = buf + sizeof(ngx_proxy_protocol_header_t);

    switch (c->sockaddr->sa_family) {

    case AF_INET:

        if (c->local_sockaddr->sa_family != AF_INET) {
            goto mixed;
        }

        header->family_transport = (NGX_PROXY_PROTOCOL_AF_INET << 4) | transport;
        header->len[0] = 0;
        header->len[1] = sizeof(ngx_proxy_protocol_inet_addrs_t);

        in = (ngx_proxy_protocol_inet_addrs_t *) p;

        ngx_memcpy(in->src_addr,
                   &((struct sockaddr_in *) c->sockaddr)->sin_addr, 4);
        ngx_memcpy(in->dst_addr,
                   &((struct sockaddr_in *) c->local_sockaddr)->sin_addr, 4);

        port = ngx_inet_get_port(c->sockaddr);
        lport = ngx_inet_get_port(c->local_sockaddr);

        in->src_port[0] = (u_char) (port >> 8);
        in->src_port[1] = (u_char) port;
        in->dst_port[0] = (u_char) (lport >> 8);
        in->dst_port[1] = (u_char) lport;

        p += sizeof(ngx_proxy_protocol_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:

        if (c->local_sockaddr->sa_family != AF_INET6) {
            goto mixed;
        }

        src6 = &((struct sockaddr_in6 *) c->sockaddr)->sin6_addr;
        dst6 = &((struct sockaddr_in6 *) c->local_sockaddr)->sin6_addr;

        port = ngx_inet_get_port(c->sockaddr);
        lport = ngx_inet_get_port(c->local_sockaddr);

        if (IN6_IS_ADDR_V4MAPPED(src6) && IN6_IS_ADDR_V4MAPPED(dst6)) {

            header->family_transport = (NGX_PROXY_PROTOCOL_AF_INET << 4) | transport;
            header->len[0] = 0;
            header->len[1] = sizeof(ngx_proxy_protocol_inet_addrs_t);

            in = (ngx_proxy_protocol_inet_addrs_t *) p;

            ngx_memcpy(in->src_addr, src6->s6_addr + 12, 4);
            ngx_memcpy(in->dst_addr, dst6->s6_addr + 12, 4);

            in->src_port[0] = (u_char) (port >> 8);
            in->src_port[1] = (u_char) port;
            in->dst_port[0] = (u_char) (lport >> 8);
            in->dst_port[1] = (u_char) lport;

            p += sizeof(ngx_proxy_protocol_inet_addrs_t);

        } else {

            header->family_transport = (NGX_PROXY_PROTOCOL_AF_INET6 << 4) | transport;
            header->len[0] = 0;
            header->len[1] = sizeof(ngx_proxy_protocol_inet6_addrs_t);

            in6 = (ngx_proxy_protocol_inet6_addrs_t *) p;

            ngx_memcpy(in6->src_addr, src6, 16);
            ngx_memcpy(in6->dst_addr, dst6, 16);

            in6->src_port[0] = (u_char) (port >> 8);
            in6->src_port[1] = (u_char) port;
            in6->dst_port[0] = (u_char) (lport >> 8);
            in6->dst_port[1] = (u_char) lport;

            p += sizeof(ngx_proxy_protocol_inet6_addrs_t);
        }

        break;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:

        if (c->local_sockaddr->sa_family != AF_UNIX) {
            goto mixed;
        }

        header->family_transport = (NGX_PROXY_PROTOCOL_AF_UNIX << 4) | transport;
        header->len[0] = 0;
        header->len[1] = sizeof(ngx_proxy_protocol_unix_addrs_t);

        un = (ngx_proxy_protocol_unix_addrs_t *) p;

        ngx_memzero(un, sizeof(ngx_proxy_protocol_unix_addrs_t));

        path_len = (c->socklen > (socklen_t) sizeof(sa_family_t))
                   ? ngx_min(c->socklen - sizeof(sa_family_t),
                             sizeof(un->src_addr))
                   : 0;

        if (path_len) {
            ngx_memcpy(un->src_addr,
                       ((struct sockaddr_un *) c->sockaddr)->sun_path,
                       path_len);
        }

        ngx_memcpy(un->dst_addr,
                   ((struct sockaddr_un *) c->local_sockaddr)->sun_path,
                   sizeof(un->dst_addr));

        p += sizeof(ngx_proxy_protocol_unix_addrs_t);

        break;

#endif

    default:

    mixed:

        ngx_log_error(NGX_LOG_CRIT, c->log, 0,
                      "PROXY protocol v2 unsupported address family");

        header->family_transport = NGX_PROXY_PROTOCOL_AF_UNSPEC << 4;
        header->len[0] = 0;
        header->len[1] = 0;

        break;
    }

    return p;
}


size_t
ngx_proxy_protocol_v2_tlvs_size(ngx_array_t *tlvs)
{
    ngx_uint_t                      i, has_ssl;
    size_t                          size, ssl_sub_total;
    ngx_proxy_protocol_write_tlv_t *tlv;

    if (tlvs == NULL || tlvs->nelts == 0) {
        return 0;
    }

    size = 0;
    has_ssl = 0;
    ssl_sub_total = 0;
    tlv = tlvs->elts;

    for (i = 0; i < tlvs->nelts; i++) {
        if (tlv[i].is_ssl_verify) {
            has_ssl = 1;
        } else if (tlv[i].is_ssl_sub) {
            has_ssl = 1;
            ssl_sub_total += 3 + tlv[i].value.len;
        } else {
            size += 3 + tlv[i].value.len;
        }
    }

    if (has_ssl) {
        size += 3 + 5 + ssl_sub_total;  /* SSL TLV header + client+verify + subtlvs */
    }

    return size;
}


u_char *
ngx_proxy_protocol_v2_write_tlvs(ngx_connection_t *c, u_char *buf,
    u_char *last, ngx_array_t *tlvs)
{
    u_char                            *p, *ssl_start;
    u_char                             client_flags;
    ngx_int_t                          verify_i;
    ngx_uint_t                         i, has_ssl, has_ssl_cn;
    uint32_t                           verify;
    uint16_t                           len, ssl_body_len;
    ngx_proxy_protocol_header_t       *header;
    ngx_proxy_protocol_tlv_t          *wire;
    ngx_proxy_protocol_write_tlv_t    *tlv;

    if (tlvs == NULL || tlvs->nelts == 0) {
        return ngx_proxy_protocol_v2_write(c, buf, last);
    }

    p = ngx_proxy_protocol_v2_write(c, buf, last);
    if (p == NULL) {
        return NULL;
    }

    header = (ngx_proxy_protocol_header_t *) buf;
    len = ngx_proxy_protocol_parse_uint16(header->len);

    tlv = tlvs->elts;
    has_ssl = 0;
    has_ssl_cn = 0;
    verify = 0xFFFFFFFF;

    for (i = 0; i < tlvs->nelts; i++) {
        if (tlv[i].is_ssl_verify) {
            has_ssl = 1;
        } else if (tlv[i].is_ssl_sub) {
            has_ssl = 1;
            len += 3 + (uint16_t) tlv[i].value.len;
            if (tlv[i].type == NGX_PROXY_PROTOCOL_V2_SUBTYPE_SSL_CN) {
                has_ssl_cn = 1;
            }
        } else {
            len += 3 + (uint16_t) tlv[i].value.len;
        }
    }

    if (has_ssl) {
        len += 3 + 5;  /* outer 0x20 TLV header + client(1) + verify(4) */
    }

    header->len[0] = (u_char) (len >> 8);
    header->len[1] = (u_char) len;

    for (i = 0; i < tlvs->nelts; i++) {
        if (tlv[i].is_ssl_sub || tlv[i].is_ssl_verify) {
            continue;
        }

        if (p + sizeof(ngx_proxy_protocol_tlv_t) + tlv[i].value.len > last) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "too small buffer for PROXY protocol v2 TLVs");
            return NULL;
        }

        wire = (ngx_proxy_protocol_tlv_t *) p;
        wire->type = (u_char) tlv[i].type;
        wire->len[0] = (u_char) (tlv[i].value.len >> 8);
        wire->len[1] = (u_char) tlv[i].value.len;
        p += sizeof(ngx_proxy_protocol_tlv_t);
        p = ngx_cpymem(p, tlv[i].value.data, tlv[i].value.len);
    }

    if (!has_ssl) {
        return p;
    }

    ssl_start = p;
    p += sizeof(ngx_proxy_protocol_tlv_t);  /* TLV header filled below */

    client_flags = NGX_PROXY_PROTOCOL_V2_CLIENT_SSL;

    if (has_ssl_cn) {
        client_flags |= NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_SESS;
#if (NGX_SSL)
        if (c->ssl != NULL && !SSL_session_reused(c->ssl->connection)) {
            client_flags |= NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_CONN;
        }
#endif
    }

    *p++ = client_flags;

    for (i = 0; i < tlvs->nelts; i++) {
        if (!tlv[i].is_ssl_verify) {
            continue;
        }

        verify_i = ngx_atoi(tlv[i].value.data, tlv[i].value.len);
        if (verify_i == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "invalid PROXY protocol ssl_verify value \"%V\"",
                          &tlv[i].value);
            return NULL;
        }

        verify = (uint32_t) verify_i;
        break;
    }

    *p++ = (u_char) (verify >> 24);
    *p++ = (u_char) (verify >> 16);
    *p++ = (u_char) (verify >> 8);
    *p++ = (u_char)  verify;

    for (i = 0; i < tlvs->nelts; i++) {
        if (!tlv[i].is_ssl_sub) {
            continue;
        }

        if (p + sizeof(ngx_proxy_protocol_tlv_t) + tlv[i].value.len > last) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "too small buffer for PROXY protocol v2 TLVs");
            return NULL;
        }

        *p++ = (u_char) tlv[i].type;
        *p++ = (u_char) (tlv[i].value.len >> 8);
        *p++ = (u_char)  tlv[i].value.len;
        p = ngx_cpymem(p, tlv[i].value.data, tlv[i].value.len);
    }

    ssl_body_len = (uint16_t) (p - ssl_start
                               - sizeof(ngx_proxy_protocol_tlv_t));
    wire = (ngx_proxy_protocol_tlv_t *) ssl_start;
    wire->type = NGX_PROXY_PROTOCOL_V2_TYPE_SSL;
    wire->len[0] = (u_char) (ssl_body_len >> 8);
    wire->len[1] = (u_char)  ssl_body_len;

    return p;
}


u_char *
ngx_proxy_protocol_v2_write_crc32c(ngx_connection_t *c, u_char *buf,
    u_char *p, u_char *last)
{
    uint16_t                      len;
    uint32_t                      crc;
    ngx_proxy_protocol_header_t  *header;
    ngx_proxy_protocol_tlv_t     *wire;

    /* type(1) + len(2) + crc32c_value(4) = 7 bytes */
    if (p + 7 > last) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "too small buffer for PROXY protocol v2 CRC32c TLV");
        return NULL;
    }

    /* Append CRC32c TLV with zeroed value field */
    wire = (ngx_proxy_protocol_tlv_t *) p;
    wire->type = NGX_PROXY_PROTOCOL_V2_TYPE_CRC32C;
    wire->len[0] = 0;
    wire->len[1] = 4;
    p += sizeof(ngx_proxy_protocol_tlv_t);

    p[0] = 0;
    p[1] = 0;
    p[2] = 0;
    p[3] = 0;
    p += 4;

    /* Update the PPv2 length field to include this TLV */
    header = (ngx_proxy_protocol_header_t *) buf;
    len = ngx_proxy_protocol_parse_uint16(header->len) + 7;
    header->len[0] = (u_char) (len >> 8);
    header->len[1] = (u_char) len;

    /* Compute CRC32c over the entire assembled header (zeroed value included) */
    crc = ngx_crc32c(buf, p - buf);

    /* Write the checksum in network byte order */
    p[-4] = (u_char) (crc >> 24);
    p[-3] = (u_char) (crc >> 16);
    p[-2] = (u_char) (crc >> 8);
    p[-1] = (u_char) crc;

    return p;
}


static u_char *
ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    u_char                             *end;
    size_t                              len;
    socklen_t                           socklen;
    ngx_uint_t                          version, command, family, transport;
    ngx_sockaddr_t                      src_sockaddr, dst_sockaddr;
    ngx_proxy_protocol_t               *pp;
    ngx_proxy_protocol_header_t        *header;
    ngx_proxy_protocol_inet_addrs_t    *in;
#if (NGX_HAVE_INET6)
    ngx_proxy_protocol_inet6_addrs_t   *in6;
#endif

    header = (ngx_proxy_protocol_header_t *) buf;

    buf += sizeof(ngx_proxy_protocol_header_t);

    version = header->version_command >> 4;

    if (version != 2) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "unknown PROXY protocol version: %ui", version);
        return NULL;
    }

    len = ngx_proxy_protocol_parse_uint16(header->len);

    if ((size_t) (last - buf) < len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "header is too large");
        return NULL;
    }

    end = buf + len;

    command = header->version_command & 0x0f;

    /* only PROXY is supported */
    if (command != 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported command %ui", command);
        return end;
    }

    transport = header->family_transport & 0x0f;

    /* only STREAM is supported */
    if (transport != 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported transport %ui",
                       transport);
        return end;
    }

    pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    family = header->family_transport >> 4;

    switch (family) {

    case NGX_PROXY_PROTOCOL_AF_INET:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet_addrs_t)) {
            return NULL;
        }

        in = (ngx_proxy_protocol_inet_addrs_t *) buf;

        src_sockaddr.sockaddr_in.sin_family = AF_INET;
        src_sockaddr.sockaddr_in.sin_port = 0;
        ngx_memcpy(&src_sockaddr.sockaddr_in.sin_addr, in->src_addr, 4);

        dst_sockaddr.sockaddr_in.sin_family = AF_INET;
        dst_sockaddr.sockaddr_in.sin_port = 0;
        ngx_memcpy(&dst_sockaddr.sockaddr_in.sin_addr, in->dst_addr, 4);

        pp->src_port = ngx_proxy_protocol_parse_uint16(in->src_port);
        pp->dst_port = ngx_proxy_protocol_parse_uint16(in->dst_port);

        socklen = sizeof(struct sockaddr_in);

        buf += sizeof(ngx_proxy_protocol_inet_addrs_t);

        break;

#if (NGX_HAVE_INET6)

    case NGX_PROXY_PROTOCOL_AF_INET6:

        if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet6_addrs_t)) {
            return NULL;
        }

        in6 = (ngx_proxy_protocol_inet6_addrs_t *) buf;

        src_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        src_sockaddr.sockaddr_in6.sin6_port = 0;
        ngx_memcpy(&src_sockaddr.sockaddr_in6.sin6_addr, in6->src_addr, 16);

        dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        dst_sockaddr.sockaddr_in6.sin6_port = 0;
        ngx_memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, in6->dst_addr, 16);

        pp->src_port = ngx_proxy_protocol_parse_uint16(in6->src_port);
        pp->dst_port = ngx_proxy_protocol_parse_uint16(in6->dst_port);

        socklen = sizeof(struct sockaddr_in6);

        buf += sizeof(ngx_proxy_protocol_inet6_addrs_t);

        break;

#endif

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported address family %ui",
                       family);
        return end;
    }

    pp->src_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (pp->src_addr.data == NULL) {
        return NULL;
    }

    pp->src_addr.len = ngx_sock_ntop(&src_sockaddr.sockaddr, socklen,
                                     pp->src_addr.data, NGX_SOCKADDR_STRLEN, 0);

    pp->dst_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (pp->dst_addr.data == NULL) {
        return NULL;
    }

    pp->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, socklen,
                                     pp->dst_addr.data, NGX_SOCKADDR_STRLEN, 0);

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    if (buf < end) {
        pp->tlvs.data = ngx_pnalloc(c->pool, end - buf);
        if (pp->tlvs.data == NULL) {
            return NULL;
        }

        ngx_memcpy(pp->tlvs.data, buf, end - buf);
        pp->tlvs.len = end - buf;
    }

    c->proxy_protocol = pp;

    return end;
}


ngx_int_t
ngx_proxy_protocol_tlv_type(ngx_str_t *name, ngx_uint_t *typep,
    ngx_uint_t *is_ssl_subp, ngx_uint_t *is_ssl_verifyp,
    ngx_uint_t *is_ssl_rawp)
{
    ngx_int_t                       type;
    ngx_proxy_protocol_tlv_name_t  *tn;

    for (tn = ngx_proxy_protocol_tlv_names; tn->name.len; tn++) {
        if (name->len == tn->name.len
            && ngx_strncmp(name->data, tn->name.data, name->len) == 0)
        {
            *typep = tn->type;
            *is_ssl_subp = tn->is_ssl_sub;
            *is_ssl_verifyp = tn->is_ssl_verify;
            *is_ssl_rawp = tn->is_ssl_raw;
            return NGX_OK;
        }
    }

    /* ssl_0x<hex>: explicit hex type for an SSL sub-TLV */
    if (name->len >= 7
        && name->data[0] == 's' && name->data[1] == 's'
        && name->data[2] == 'l' && name->data[3] == '_'
        && name->data[4] == '0'
        && (name->data[5] == 'x' || name->data[5] == 'X'))
    {
        type = ngx_hextoi(name->data + 6, name->len - 6);
        if (type == NGX_ERROR || type > 255) {
            return NGX_ERROR;
        }
        *typep = (ngx_uint_t) type;
        *is_ssl_subp = 1;
        *is_ssl_verifyp = 0;
        *is_ssl_rawp = 0;
        return NGX_OK;
    }

    /* 0x<hex> numeric type */
    if (name->len > 2
        && name->data[0] == '0'
        && (name->data[1] == 'x' || name->data[1] == 'X'))
    {
        type = ngx_hextoi(name->data + 2, name->len - 2);
        if (type == NGX_ERROR || type > 255) {
            return NGX_ERROR;
        }
        *typep = (ngx_uint_t) type;
        *is_ssl_subp = 0;
        *is_ssl_verifyp = 0;
        *is_ssl_rawp = 0;
        return NGX_OK;
    }

    /* decimal numeric type */
    type = ngx_atoi(name->data, name->len);
    if (type == NGX_ERROR || type > 255) {
        return NGX_DECLINED;
    }

    *typep = (ngx_uint_t) type;
    *is_ssl_subp = 0;
    *is_ssl_verifyp = 0;
    *is_ssl_rawp = 0;
    return NGX_OK;
}


char *
ngx_proxy_protocol_v2_add_tlv(ngx_conf_t *cf, ngx_array_t **tlvsp,
    ngx_str_t *name, void *cv)
{
    ngx_int_t                       rc;
    ngx_uint_t                      j, type;
    ngx_uint_t                      is_ssl_sub, is_ssl_verify, is_ssl_raw;
    ngx_proxy_protocol_conf_tlv_t  *tlv, *existing;

    rc = ngx_proxy_protocol_tlv_type(name, &type, &is_ssl_sub, &is_ssl_verify,
                                     &is_ssl_raw);
    if (rc == NGX_DECLINED) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown PROXY protocol TLV \"%V\"", name);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid PROXY protocol TLV \"%V\"", name);
        return NGX_CONF_ERROR;
    }

    if (!is_ssl_verify && type == NGX_PROXY_PROTOCOL_V2_TYPE_CRC32C) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "TLV type 0x03 is reserved for CRC32c checksum, "
                           "use the \"proxy_protocol_crc32c\" directive");
        return NGX_CONF_ERROR;
    }

    if (*tlvsp == NGX_CONF_UNSET_PTR) {
        *tlvsp = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_proxy_protocol_conf_tlv_t));
        if (*tlvsp == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
        existing = (*tlvsp)->elts;
        for (j = 0; j < (*tlvsp)->nelts; j++) {
            if (is_ssl_raw) {
                if (existing[j].is_ssl_raw) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate PROXY protocol TLV "
                                       "\"ssl\"");
                    return NGX_CONF_ERROR;
                }
                if (existing[j].is_ssl_sub || existing[j].is_ssl_verify) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "\"ssl\" TLV conflicts with ssl "
                                       "sub-TLV directives");
                    return NGX_CONF_ERROR;
                }
                continue;
            }
            if (existing[j].is_ssl_raw && (is_ssl_sub || is_ssl_verify)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ssl sub-TLV directives conflict with "
                                   "\"ssl\" TLV");
                return NGX_CONF_ERROR;
            }
            if (is_ssl_verify) {
                if (existing[j].is_ssl_verify) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate PROXY protocol TLV "
                                       "\"ssl_verify\"");
                    return NGX_CONF_ERROR;
                }
            } else if (!existing[j].is_ssl_verify
                       && !existing[j].is_ssl_raw
                       && existing[j].is_ssl_sub == is_ssl_sub
                       && existing[j].type == type)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate PROXY protocol TLV type "
                                   "\"%V\"", name);
                return NGX_CONF_ERROR;
            }
        }
    }

    tlv = ngx_array_push(*tlvsp);
    if (tlv == NULL) {
        return NGX_CONF_ERROR;
    }

    tlv->type = type;
    tlv->is_ssl_sub = is_ssl_sub;
    tlv->is_ssl_verify = is_ssl_verify;
    tlv->is_ssl_raw = is_ssl_raw;
    tlv->cv = cv;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value)
{
    uint32_t                       verify;
    ngx_int_t                      rc;
    ngx_uint_t                     type, is_ssl_sub, is_ssl_verify, is_ssl_raw;
    ngx_str_t                      ssl, *tlvs;
    ngx_proxy_protocol_tlv_ssl_t  *tlv_ssl;

    if (c->proxy_protocol == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 get tlv \"%V\"", name);

    rc = ngx_proxy_protocol_tlv_type(name, &type, &is_ssl_sub, &is_ssl_verify,
                                     &is_ssl_raw);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      rc == NGX_ERROR ? "invalid PROXY protocol TLV \"%V\""
                                      : "unknown PROXY protocol TLV \"%V\"",
                      name);
        return rc;
    }

    tlvs = &c->proxy_protocol->tlvs;

    if (is_ssl_sub || is_ssl_verify) {

        rc = ngx_proxy_protocol_lookup_tlv(c, tlvs,
                                           NGX_PROXY_PROTOCOL_V2_TYPE_SSL,
                                           &ssl);
        if (rc != NGX_OK) {
            return rc;
        }

        if (ssl.len < sizeof(ngx_proxy_protocol_tlv_ssl_t)) {
            return NGX_ERROR;
        }

        if (is_ssl_verify) {
            tlv_ssl = (ngx_proxy_protocol_tlv_ssl_t *) ssl.data;
            verify = ngx_proxy_protocol_parse_uint32(tlv_ssl->verify);

            value->data = ngx_pnalloc(c->pool, NGX_INT32_LEN);
            if (value->data == NULL) {
                return NGX_ERROR;
            }

            value->len = ngx_sprintf(value->data, "%uD", verify)
                         - value->data;
            return NGX_OK;
        }

        ssl.data += sizeof(ngx_proxy_protocol_tlv_ssl_t);
        ssl.len -= sizeof(ngx_proxy_protocol_tlv_ssl_t);
        tlvs = &ssl;
    }

    return ngx_proxy_protocol_lookup_tlv(c, tlvs, type, value);
}


static ngx_int_t
ngx_proxy_protocol_lookup_tlv(ngx_connection_t *c, ngx_str_t *tlvs,
    ngx_uint_t type, ngx_str_t *value)
{
    u_char                    *p;
    size_t                     n, len;
    ngx_proxy_protocol_tlv_t  *tlv;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 lookup tlv:%02xi", type);

    p = tlvs->data;
    n = tlvs->len;

    while (n) {
        if (n < sizeof(ngx_proxy_protocol_tlv_t)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "broken PROXY protocol TLV");
            return NGX_ERROR;
        }

        tlv = (ngx_proxy_protocol_tlv_t *) p;
        len = ngx_proxy_protocol_parse_uint16(tlv->len);

        p += sizeof(ngx_proxy_protocol_tlv_t);
        n -= sizeof(ngx_proxy_protocol_tlv_t);

        if (n < len) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "broken PROXY protocol TLV");
            return NGX_ERROR;
        }

        if (tlv->type == type) {
            value->data = p;
            value->len = len;
            return NGX_OK;
        }

        p += len;
        n -= len;
    }

    return NGX_DECLINED;
}
