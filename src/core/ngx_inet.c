
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_int_t ngx_parse_unix_domain_url(ngx_pool_t *pool, ngx_url_t *u);
static ngx_int_t ngx_parse_inet_url(ngx_pool_t *pool, ngx_url_t *u);
static ngx_int_t ngx_parse_inet6_url(ngx_pool_t *pool, ngx_url_t *u);


in_addr_t
ngx_inet_addr(u_char *text, size_t len)
{
    u_char      *p, c;
    in_addr_t    addr;
    ngx_uint_t   octet, n;

    addr = 0;
    octet = 0;
    n = 0;

    for (p = text; p < text + len; p++) {

        c = *p;

        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            continue;
        }

        if (c == '.' && octet < 256) {
            addr = (addr << 8) + octet;
            octet = 0;
            n++;
            continue;
        }

        return INADDR_NONE;
    }

    if (n == 3 && octet < 256) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }

    return INADDR_NONE;
}


#if (NGX_HAVE_INET6)

ngx_int_t
ngx_inet6_addr(u_char *p, size_t len, u_char *addr)
{
    u_char      c, *zero, *digit, *s, *d;
    size_t      len4;
    ngx_uint_t  n, nibbles, word;

    if (len == 0) {
        return NGX_ERROR;
    }

    zero = NULL;
    digit = NULL;
    len4 = 0;
    nibbles = 0;
    word = 0;
    n = 8;

    if (p[0] == ':') {
        p++;
        len--;
    }

    for (/* void */; len; len--) {
        c = *p++;

        if (c == ':') {
            if (nibbles) {
                digit = p;
                len4 = len;
                *addr++ = (u_char) (word >> 8);
                *addr++ = (u_char) (word & 0xff);

                if (--n) {
                    nibbles = 0;
                    word = 0;
                    continue;
                }

            } else {
                if (zero == NULL) {
                    digit = p;
                    len4 = len;
                    zero = addr;
                    continue;
                }
            }

            return NGX_ERROR;
        }

        if (c == '.' && nibbles) {
            if (n < 2 || digit == NULL) {
                return NGX_ERROR;
            }

            word = ngx_inet_addr(digit, len4 - 1);
            if (word == INADDR_NONE) {
                return NGX_ERROR;
            }

            word = ntohl(word);
            *addr++ = (u_char) ((word >> 24) & 0xff);
            *addr++ = (u_char) ((word >> 16) & 0xff);
            n--;
            break;
        }

        if (++nibbles > 4) {
            return NGX_ERROR;
        }

        if (c >= '0' && c <= '9') {
            word = word * 16 + (c - '0');
            continue;
        }

        c |= 0x20;

        if (c >= 'a' && c <= 'f') {
            word = word * 16 + (c - 'a') + 10;
            continue;
        }

        return NGX_ERROR;
    }

    if (nibbles == 0 && zero == NULL) {
        return NGX_ERROR;
    }

    *addr++ = (u_char) (word >> 8);
    *addr++ = (u_char) (word & 0xff);

    if (--n) {
        if (zero) {
            n *= 2;
            s = addr - 1;
            d = s + n;
            while (s >= zero) {
                *d-- = *s--;
            }
            ngx_memzero(zero, n);
            return NGX_OK;
        }

    } else {
        if (zero == NULL) {
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

#endif


size_t
ngx_sock_ntop(struct sockaddr *sa, u_char *text, size_t len, ngx_uint_t port)
{
    u_char               *p;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    size_t                n;
    struct sockaddr_in6  *sin6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un   *saun;
#endif

    switch (sa->sa_family) {

    case AF_INET:

        sin = (struct sockaddr_in *) sa;
        p = (u_char *) &sin->sin_addr;

        if (port) {
            p = ngx_snprintf(text, len, "%ud.%ud.%ud.%ud:%d",
                             p[0], p[1], p[2], p[3], ntohs(sin->sin_port));
        } else {
            p = ngx_snprintf(text, len, "%ud.%ud.%ud.%ud",
                             p[0], p[1], p[2], p[3]);
        }

        return (p - text);

#if (NGX_HAVE_INET6)

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *) sa;

        n = 0;

        if (port) {
            text[n++] = '[';
        }

        n = ngx_inet6_ntop(sin6->sin6_addr.s6_addr, &text[n], len);

        if (port) {
            n = ngx_sprintf(&text[1 + n], "]:%d",
                            ntohs(sin6->sin6_port)) - text;
        }

        return n;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        saun = (struct sockaddr_un *) sa;

        /* we do not include trailing zero in address length */

        return ngx_snprintf(text, len, "unix:%s%Z", saun->sun_path) - text - 1;

#endif

    default:
        return 0;
    }
}


size_t
ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    u_char  *p;

    switch (family) {

    case AF_INET:

        p = addr;

        return ngx_snprintf(text, len, "%ud.%ud.%ud.%ud",
                            p[0], p[1], p[2], p[3])
               - text;

#if (NGX_HAVE_INET6)

    case AF_INET6:
        return ngx_inet6_ntop(addr, text, len);

#endif

    default:
        return 0;
    }
}


#if (NGX_HAVE_INET6)

size_t
ngx_inet6_ntop(u_char *p, u_char *text, size_t len)
{
    u_char      *dst;
    size_t       max, n;
    ngx_uint_t   i, zero, last;

    if (len < NGX_INET6_ADDRSTRLEN) {
        return 0;
    }

    zero = (ngx_uint_t) -1;
    last = (ngx_uint_t) -1;
    max = 1;
    n = 0;

    for (i = 0; i < 16; i += 2) {

        if (p[i] || p[i + 1]) {

            if (max < n) {
                zero = last;
                max = n;
            }

            n = 0;
            continue;
        }

        if (n++ == 0) {
            last = i;
        }
    }

    if (max < n) {
        zero = last;
        max = n;
    }

    dst = text;
    n = 16;

    if (zero == 0) {

        if ((max == 5 && p[10] == 0xff && p[11] == 0xff)
            || (max == 6)
            || (max == 7 && p[14] != 0 && p[15] != 1))
        {
            n = 12;
        }

        *dst++ = ':';
    }

    for (i = 0; i < n; i += 2) {

        if (i == zero) {
            *dst++ = ':';
            i += (max - 1) * 2;
            continue;
        }

        dst = ngx_sprintf(dst, "%uxi", p[i] * 256 + p[i + 1]);

        if (i < 14) {
            *dst++ = ':';
        }
    }

    if (n == 12) {
        dst = ngx_sprintf(dst, "%ud.%ud.%ud.%ud", p[12], p[13], p[14], p[15]);
    }

    return dst - text;
}

#endif


ngx_int_t
ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr)
{
    u_char      *addr, *mask, *last;
    size_t       len;
    ngx_int_t    shift;
#if (NGX_HAVE_INET6)
    ngx_int_t    rc;
    ngx_uint_t   s, i;
#endif

    addr = text->data;
    last = addr + text->len;

    mask = ngx_strlchr(addr, last, '/');
    len = (mask ? mask : last) - addr;

    cidr->u.in.addr = ngx_inet_addr(addr, len);

    if (cidr->u.in.addr != INADDR_NONE) {
        cidr->family = AF_INET;

        if (mask == NULL) {
            cidr->u.in.mask = 0xffffffff;
            return NGX_OK;
        }

#if (NGX_HAVE_INET6)
    } else if (ngx_inet6_addr(addr, len, cidr->u.in6.addr.s6_addr) == NGX_OK) {
        cidr->family = AF_INET6;

        if (mask == NULL) {
            ngx_memset(cidr->u.in6.mask.s6_addr, 0xff, 16);
            return NGX_OK;
        }

#endif
    } else {
        return NGX_ERROR;
    }

    mask++;

    shift = ngx_atoi(mask, last - mask);
    if (shift == NGX_ERROR) {
        return NGX_ERROR;
    }

    switch (cidr->family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        if (shift > 128) {
            return NGX_ERROR;
        }

        addr = cidr->u.in6.addr.s6_addr;
        mask = cidr->u.in6.mask.s6_addr;
        rc = NGX_OK;

        for (i = 0; i < 16; i++) {

            s = (shift > 8) ? 8 : shift;
            shift -= s;

            mask[i] = (u_char) (0xffu << (8 - s));

            if (addr[i] != (addr[i] & mask[i])) {
                rc = NGX_DONE;
                addr[i] &= mask[i];
            }
        }

        return rc;
#endif

    default: /* AF_INET */
        if (shift > 32) {
            return NGX_ERROR;
        }

        if (shift) {
            cidr->u.in.mask = htonl((uint32_t) (0xffffffffu << (32 - shift)));

        } else {
            /* x86 compilers use a shl instruction that shifts by modulo 32 */
            cidr->u.in.mask = 0;
        }

        if (cidr->u.in.addr == (cidr->u.in.addr & cidr->u.in.mask)) {
            return NGX_OK;
        }

        cidr->u.in.addr &= cidr->u.in.mask;

        return NGX_DONE;
    }
}


ngx_int_t
ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text, size_t len)
{
    in_addr_t             inaddr;
    ngx_uint_t            family;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct in6_addr       inaddr6;
    struct sockaddr_in6  *sin6;

    /*
     * prevent MSVC8 warning:
     *    potentially uninitialized local variable 'inaddr6' used
     */
    ngx_memzero(&inaddr6, sizeof(struct in6_addr));
#endif

    inaddr = ngx_inet_addr(text, len);

    if (inaddr != INADDR_NONE) {
        family = AF_INET;
        len = sizeof(struct sockaddr_in);

#if (NGX_HAVE_INET6)
    } else if (ngx_inet6_addr(text, len, inaddr6.s6_addr) == NGX_OK) {
        family = AF_INET6;
        len = sizeof(struct sockaddr_in6);

#endif
    } else {
        return NGX_DECLINED;
    }

    addr->sockaddr = ngx_pcalloc(pool, len);
    if (addr->sockaddr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr->sa_family = (u_char) family;
    addr->socklen = len;

    switch (family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;
        ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) addr->sockaddr;
        sin->sin_addr.s_addr = inaddr;
        break;
    }

    return NGX_OK;
}


ngx_int_t
ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char  *p;

    p = u->url.data;

    if (ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        return ngx_parse_unix_domain_url(pool, u);
    }

    if (p[0] == '[') {
        return ngx_parse_inet6_url(pool, u);
    }

    return ngx_parse_inet_url(pool, u);
}


static ngx_int_t
ngx_parse_unix_domain_url(ngx_pool_t *pool, ngx_url_t *u)
{
#if (NGX_HAVE_UNIX_DOMAIN)
    u_char              *path, *uri, *last;
    size_t               len;
    struct sockaddr_un  *saun;

    len = u->url.len;
    path = u->url.data;

    path += 5;
    len -= 5;

    if (u->uri_part) {

        last = path + len;
        uri = ngx_strlchr(path, last, ':');

        if (uri) {
            len = uri - path;
            uri++;
            u->uri.len = last - uri;
            u->uri.data = uri;
        }
    }

    if (len == 0) {
        u->err = "no path in the unix domain socket";
        return NGX_ERROR;
    }

    u->host.len = len++;
    u->host.data = path;

    if (len > sizeof(saun->sun_path)) {
        u->err = "too long path in the unix domain socket";
        return NGX_ERROR;
    }

    u->socklen = sizeof(struct sockaddr_un);
    saun = (struct sockaddr_un *) &u->sockaddr;
    saun->sun_family = AF_UNIX;
    (void) ngx_cpystrn((u_char *) saun->sun_path, path, len);

    u->addrs = ngx_pcalloc(pool, sizeof(ngx_addr_t));
    if (u->addrs == NULL) {
        return NGX_ERROR;
    }

    saun = ngx_pcalloc(pool, sizeof(struct sockaddr_un));
    if (saun == NULL) {
        return NGX_ERROR;
    }

    u->family = AF_UNIX;
    u->naddrs = 1;

    saun->sun_family = AF_UNIX;
    (void) ngx_cpystrn((u_char *) saun->sun_path, path, len);

    u->addrs[0].sockaddr = (struct sockaddr *) saun;
    u->addrs[0].socklen = sizeof(struct sockaddr_un);
    u->addrs[0].name.len = len + 4;
    u->addrs[0].name.data = u->url.data;

    return NGX_OK;

#else

    u->err = "the unix domain sockets are not supported on this platform";

    return NGX_ERROR;

#endif
}


static ngx_int_t
ngx_parse_inet_url(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char               *p, *host, *port, *last, *uri, *args;
    size_t                len;
    ngx_int_t             n;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    u->socklen = sizeof(struct sockaddr_in);
    sin = (struct sockaddr_in *) &u->sockaddr;
    sin->sin_family = AF_INET;

    u->family = AF_INET;

    host = u->url.data;

    last = host + u->url.len;

    port = ngx_strlchr(host, last, ':');

    uri = ngx_strlchr(host, last, '/');

    args = ngx_strlchr(host, last, '?');

    if (args) {
        if (uri == NULL || args < uri) {
            uri = args;
        }
    }

    if (uri) {
        if (u->listen || !u->uri_part) {
            u->err = "invalid host";
            return NGX_ERROR;
        }

        u->uri.len = last - uri;
        u->uri.data = uri;

        last = uri;

        if (uri < port) {
            port = NULL;
        }
    }

    if (port) {
        port++;

        len = last - port;

        n = ngx_atoi(port, len);

        if (n < 1 || n > 65535) {
            u->err = "invalid port";
            return NGX_ERROR;
        }

        u->port = (in_port_t) n;
        sin->sin_port = htons((in_port_t) n);

        u->port_text.len = len;
        u->port_text.data = port;

        last = port - 1;

    } else {
        if (uri == NULL) {

            if (u->listen) {

                /* test value as port only */

                n = ngx_atoi(host, last - host);

                if (n != NGX_ERROR) {

                    if (n < 1 || n > 65535) {
                        u->err = "invalid port";
                        return NGX_ERROR;
                    }

                    u->port = (in_port_t) n;
                    sin->sin_port = htons((in_port_t) n);

                    u->port_text.len = last - host;
                    u->port_text.data = host;

                    u->wildcard = 1;

                    return NGX_OK;
                }
            }
        }

        u->no_port = 1;
        u->port = u->default_port;
        sin->sin_port = htons(u->default_port);
    }

    len = last - host;

    if (len == 0) {
        u->err = "no host";
        return NGX_ERROR;
    }

    u->host.len = len;
    u->host.data = host;

    if (u->listen && len == 1 && *host == '*') {
        sin->sin_addr.s_addr = INADDR_ANY;
        u->wildcard = 1;
        return NGX_OK;
    }

    sin->sin_addr.s_addr = ngx_inet_addr(host, len);

    if (sin->sin_addr.s_addr != INADDR_NONE) {

        if (sin->sin_addr.s_addr == INADDR_ANY) {
            u->wildcard = 1;
        }

        u->naddrs = 1;

        u->addrs = ngx_pcalloc(pool, sizeof(ngx_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }

        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(sin, u->sockaddr, sizeof(struct sockaddr_in));

        u->addrs[0].sockaddr = (struct sockaddr *) sin;
        u->addrs[0].socklen = sizeof(struct sockaddr_in);

        p = ngx_pnalloc(pool, u->host.len + sizeof(":65535") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        u->addrs[0].name.len = ngx_sprintf(p, "%V:%d",
                                           &u->host, u->port) - p;
        u->addrs[0].name.data = p;

        return NGX_OK;
    }

    if (u->no_resolve) {
        return NGX_OK;
    }

    if (ngx_inet_resolve_host(pool, u) != NGX_OK) {
        return NGX_ERROR;
    }

    u->family = u->addrs[0].sockaddr->sa_family;
    u->socklen = u->addrs[0].socklen;
    ngx_memcpy(u->sockaddr, u->addrs[0].sockaddr, u->addrs[0].socklen);

    switch (u->family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) &u->sockaddr;

        if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
            u->wildcard = 1;
        }

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) &u->sockaddr;

        if (sin->sin_addr.s_addr == INADDR_ANY) {
            u->wildcard = 1;
        }

        break;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_parse_inet6_url(ngx_pool_t *pool, ngx_url_t *u)
{
#if (NGX_HAVE_INET6)
    u_char               *p, *host, *port, *last, *uri;
    size_t                len;
    ngx_int_t             n;
    struct sockaddr_in6  *sin6;

    u->socklen = sizeof(struct sockaddr_in6);
    sin6 = (struct sockaddr_in6 *) &u->sockaddr;
    sin6->sin6_family = AF_INET6;

    host = u->url.data + 1;

    last = u->url.data + u->url.len;

    p = ngx_strlchr(host, last, ']');

    if (p == NULL) {
        u->err = "invalid host";
        return NGX_ERROR;
    }

    if (last - p) {

        port = p + 1;

        uri = ngx_strlchr(port, last, '/');

        if (uri) {
            if (u->listen || !u->uri_part) {
                u->err = "invalid host";
                return NGX_ERROR;
            }

            u->uri.len = last - uri;
            u->uri.data = uri;

            last = uri;
        }

        if (*port == ':') {
            port++;

            len = last - port;

            n = ngx_atoi(port, len);

            if (n < 1 || n > 65535) {
                u->err = "invalid port";
                return NGX_ERROR;
            }

            u->port = (in_port_t) n;
            sin6->sin6_port = htons((in_port_t) n);

            u->port_text.len = len;
            u->port_text.data = port;

        } else {
            u->no_port = 1;
            u->port = u->default_port;
            sin6->sin6_port = htons(u->default_port);
        }
    }

    len = p - host;

    if (len == 0) {
        u->err = "no host";
        return NGX_ERROR;
    }

    u->host.len = len + 2;
    u->host.data = host - 1;

    if (ngx_inet6_addr(host, len, sin6->sin6_addr.s6_addr) != NGX_OK) {
        u->err = "invalid IPv6 address";
        return NGX_ERROR;
    }

    if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
        u->wildcard = 1;
    }

    u->family = AF_INET6;
    u->naddrs = 1;

    u->addrs = ngx_pcalloc(pool, sizeof(ngx_addr_t));
    if (u->addrs == NULL) {
        return NGX_ERROR;
    }

    sin6 = ngx_pcalloc(pool, sizeof(struct sockaddr_in6));
    if (sin6 == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sin6, u->sockaddr, sizeof(struct sockaddr_in6));

    u->addrs[0].sockaddr = (struct sockaddr *) sin6;
    u->addrs[0].socklen = sizeof(struct sockaddr_in6);

    p = ngx_pnalloc(pool, u->host.len + sizeof(":65535") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    u->addrs[0].name.len = ngx_sprintf(p, "%V:%d",
                                       &u->host, u->port) - p;
    u->addrs[0].name.data = p;

    return NGX_OK;

#else

    u->err = "the INET6 sockets are not supported on this platform";

    return NGX_ERROR;

#endif
}


#if (NGX_HAVE_GETADDRINFO && NGX_HAVE_INET6)

ngx_int_t
ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char               *p, *host;
    size_t                len;
    in_port_t             port;
    ngx_uint_t            i;
    struct addrinfo       hints, *res, *rp;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    port = htons(u->port);

    host = ngx_alloc(u->host.len + 1, pool->log);
    if (host == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);

    ngx_memzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo((char *) host, NULL, &hints, &res) != 0) {
        u->err = "host not found";
        ngx_free(host);
        return NGX_ERROR;
    }

    ngx_free(host);

    for (i = 0, rp = res; rp != NULL; rp = rp->ai_next) {

        switch (rp->ai_family) {

        case AF_INET:
        case AF_INET6:
            break;

        default:
            continue;
        }

        i++;
    }

    if (i == 0) {
        u->err = "host not found";
        goto failed;
    }

    /* MP: ngx_shared_palloc() */

    u->addrs = ngx_pcalloc(pool, i * sizeof(ngx_addr_t));
    if (u->addrs == NULL) {
        goto failed;
    }

    u->naddrs = i;

    i = 0;

    /* AF_INET addresses first */

    for (rp = res; rp != NULL; rp = rp->ai_next) {

        if (rp->ai_family != AF_INET) {
            continue;
        }

        sin = ngx_pcalloc(pool, rp->ai_addrlen);
        if (sin == NULL) {
            goto failed;
        }

        ngx_memcpy(sin, rp->ai_addr, rp->ai_addrlen);

        sin->sin_port = port;

        u->addrs[i].sockaddr = (struct sockaddr *) sin;
        u->addrs[i].socklen = rp->ai_addrlen;

        len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;

        p = ngx_pnalloc(pool, len);
        if (p == NULL) {
            goto failed;
        }

        len = ngx_sock_ntop((struct sockaddr *) sin, p, len, 1);

        u->addrs[i].name.len = len;
        u->addrs[i].name.data = p;

        i++;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {

        if (rp->ai_family != AF_INET6) {
            continue;
        }

        sin6 = ngx_pcalloc(pool, rp->ai_addrlen);
        if (sin6 == NULL) {
            goto failed;
        }

        ngx_memcpy(sin6, rp->ai_addr, rp->ai_addrlen);

        sin6->sin6_port = port;

        u->addrs[i].sockaddr = (struct sockaddr *) sin6;
        u->addrs[i].socklen = rp->ai_addrlen;

        len = NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1;

        p = ngx_pnalloc(pool, len);
        if (p == NULL) {
            goto failed;
        }

        len = ngx_sock_ntop((struct sockaddr *) sin6, p, len, 1);

        u->addrs[i].name.len = len;
        u->addrs[i].name.data = p;

        i++;
    }

    freeaddrinfo(res);
    return NGX_OK;

failed:

    freeaddrinfo(res);
    return NGX_ERROR;
}

#else /* !NGX_HAVE_GETADDRINFO || !NGX_HAVE_INET6 */

ngx_int_t
ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char              *p, *host;
    size_t               len;
    in_port_t            port;
    in_addr_t            in_addr;
    ngx_uint_t           i;
    struct hostent      *h;
    struct sockaddr_in  *sin;

    /* AF_INET only */

    port = htons(u->port);

    in_addr = ngx_inet_addr(u->host.data, u->host.len);

    if (in_addr == INADDR_NONE) {
        host = ngx_alloc(u->host.len + 1, pool->log);
        if (host == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);

        h = gethostbyname((char *) host);

        ngx_free(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            u->err = "host not found";
            return NGX_ERROR;
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        /* MP: ngx_shared_palloc() */

        u->addrs = ngx_pcalloc(pool, i * sizeof(ngx_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }

        u->naddrs = i;

        for (i = 0; i < u->naddrs; i++) {

            sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NGX_ERROR;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = port;
            sin->sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);

            u->addrs[i].sockaddr = (struct sockaddr *) sin;
            u->addrs[i].socklen = sizeof(struct sockaddr_in);

            len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;

            p = ngx_pnalloc(pool, len);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_sock_ntop((struct sockaddr *) sin, p, len, 1);

            u->addrs[i].name.len = len;
            u->addrs[i].name.data = p;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        u->addrs = ngx_pcalloc(pool, sizeof(ngx_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }

        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        u->naddrs = 1;

        sin->sin_family = AF_INET;
        sin->sin_port = port;
        sin->sin_addr.s_addr = in_addr;

        u->addrs[0].sockaddr = (struct sockaddr *) sin;
        u->addrs[0].socklen = sizeof(struct sockaddr_in);

        p = ngx_pnalloc(pool, u->host.len + sizeof(":65535") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        u->addrs[0].name.len = ngx_sprintf(p, "%V:%d",
                                           &u->host, ntohs(port)) - p;
        u->addrs[0].name.data = p;
    }

    return NGX_OK;
}

#endif /* NGX_HAVE_GETADDRINFO && NGX_HAVE_INET6 */
