
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_int_t ngx_parse_unix_domain_url(ngx_pool_t *pool, ngx_url_t *u);
static ngx_int_t ngx_parse_inet_url(ngx_pool_t *pool, ngx_url_t *u);


/* AF_INET only */

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

    if (n != 3) {
        return INADDR_NONE;
    }

    if (octet < 256) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }

    return INADDR_NONE;
}


/* AF_INET only */

size_t
ngx_sock_ntop(struct sockaddr *sa, u_char *text, size_t len)
{
    u_char              *p;
    struct sockaddr_in  *sin;

    if (sa->sa_family == AF_INET) {

        sin = (struct sockaddr_in *) sa;
        p = (u_char *) &sin->sin_addr;

        return ngx_snprintf(text, len, "%ud.%ud.%ud.%ud",
                            p[0], p[1], p[2], p[3])
               - text;
    }

    return 0;
}


size_t
ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    u_char  *p;

    if (family == AF_INET) {

        p = (u_char *) addr;

        return ngx_snprintf(text, len, "%ud.%ud.%ud.%ud",
                            p[0], p[1], p[2], p[3])
               - text;
    }

    return 0;
}


/* AF_INET only */

ngx_int_t
ngx_ptocidr(ngx_str_t *text, void *cidr)
{
    u_char           *addr, *mask, *last;
    ngx_int_t         shift;
    ngx_inet_cidr_t  *in_cidr;

    in_cidr = cidr;
    addr = text->data;
    last = addr + text->len;

    mask = ngx_strlchr(addr, last, '/');

    in_cidr->addr = ngx_inet_addr(addr, (mask ? mask : last) - addr);

    if (in_cidr->addr == INADDR_NONE) {
        return NGX_ERROR;
    }

    if (mask == NULL) {
        in_cidr->mask = 0xffffffff;
        return NGX_OK;
    }

    mask++;

    shift = ngx_atoi(mask, last - mask);
    if (shift == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (shift == 0) {

        /* the x86 compilers use the shl instruction that shifts by modulo 32 */

        in_cidr->mask = 0;

        if (in_cidr->addr == 0) {
            return NGX_OK;
        }

        return NGX_DONE;
    }

    in_cidr->mask = htonl((ngx_uint_t) (0 - (1 << (32 - shift))));

    if (in_cidr->addr == (in_cidr->addr & in_cidr->mask)) {
        return NGX_OK;
    }

    in_cidr->addr &= in_cidr->mask;

    return NGX_DONE;
}


ngx_int_t
ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char  *p;

    p = u->url.data;

    if (ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        return ngx_parse_unix_domain_url(pool, u);
    }

    if ((p[0] == ':' || p[0] == '/') && !u->listen) {
        u->err = "invalid host";
        return NGX_ERROR;
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
    u->family = AF_UNIX;

    if (len > sizeof(saun->sun_path)) {
        u->err = "too long path in the unix domain socket";
        return NGX_ERROR;
    }

    u->addrs = ngx_pcalloc(pool, sizeof(ngx_peer_addr_t));
    if (u->addrs == NULL) {
        return NGX_ERROR;
    }

    saun = ngx_pcalloc(pool, sizeof(struct sockaddr_un));
    if (saun == NULL) {
        return NGX_ERROR;
    }

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
    u_char          *p, *host, *port, *last, *uri, *args;
    size_t           len;
    ngx_int_t        n;
    struct hostent  *h;

    u->family = AF_INET;

    host = u->url.data;

    last = host + u->url.len;

    port = ngx_strlchr(host, last, ':');

    uri = ngx_strlchr(host, last, '/');

    args = ngx_strlchr(host, last, '?');

    if (args) {
        if (uri == NULL) {
            uri = args;

        } else if (args < uri) {
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

        if (len == 0) {
            u->err = "invalid port";
            return NGX_ERROR;
        }

        n = ngx_atoi(port, len);

        if (n < 1 || n > 65536) {
            u->err = "invalid port";
            return NGX_ERROR;
        }

        u->port = (in_port_t) n;

        u->port_text.len = len;
        u->port_text.data = port;

        last = port - 1;

    } else {
        if (uri == NULL) {

            if (u->listen) {

                /* test value as port only */

                n = ngx_atoi(host, last - host);

                if (n != NGX_ERROR) {

                    if (n < 1 || n > 65536) {
                        u->err = "invalid port";
                        return NGX_ERROR;
                    }

                    u->port = (in_port_t) n;

                    u->port_text.len = last - host;
                    u->port_text.data = host;

                    return NGX_OK;
                }
            }
        }

        u->no_port = 1;
    }

    len = last - host;

    if (len == 0) {
        u->err = "no host";
        return NGX_ERROR;
    }

    if (len == 1 && *host == '*') {
        len = 0;
    }

    u->host.len = len;
    u->host.data = host;

    if (u->no_resolve) {
        return NGX_OK;
    }

    if (len++) {

        p = ngx_alloc(len, pool->log);
        if (p == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_cpystrn(p, host, len);

        u->addr.in_addr = inet_addr((const char *) p);

        if (u->addr.in_addr == INADDR_NONE) {
            h = gethostbyname((const char *) p);

            if (h == NULL || h->h_addr_list[0] == NULL) {
                ngx_free(p);
                u->err = "host not found";
                return NGX_ERROR;
            }

            u->addr.in_addr = *(in_addr_t *) (h->h_addr_list[0]);
        }

        ngx_free(p);

    } else {
        u->addr.in_addr = INADDR_ANY;
    }

    if (u->no_port) {
        u->port = u->default_port;
    }

    if (u->listen) {
        return NGX_OK;
    }

    if (ngx_inet_resolve_host(pool, u) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char              *p, *host;
    size_t               len;
    in_addr_t            in_addr;
    ngx_uint_t           i;
    struct hostent      *h;
    struct sockaddr_in  *sin;

    host = ngx_alloc(u->host.len + 1, pool->log);
    if (host == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);

    /* AF_INET only */

    in_addr = inet_addr((char *) host);

    if (in_addr == INADDR_NONE) {
        h = gethostbyname((char *) host);

        ngx_free(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            u->err = "host not found";
            return NGX_ERROR;
        }

        if (u->one_addr == 0) {
            for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        } else {
            i = 1;
        }

        /* MP: ngx_shared_palloc() */

        u->addrs = ngx_pcalloc(pool, i * sizeof(ngx_peer_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }

        u->naddrs = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {

            sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NGX_ERROR;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = htons(u->port);
            sin->sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);

            u->addrs[i].sockaddr = (struct sockaddr *) sin;
            u->addrs[i].socklen = sizeof(struct sockaddr_in);

            len = NGX_INET_ADDRSTRLEN + sizeof(":65536") - 1;

            p = ngx_pnalloc(pool, len);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_sock_ntop((struct sockaddr *) sin, p, len);

            u->addrs[i].name.len = ngx_sprintf(&p[len], ":%d", u->port) - p;
            u->addrs[i].name.data = p;
        }

    } else {

        ngx_free(host);

        /* MP: ngx_shared_palloc() */

        u->addrs = ngx_pcalloc(pool, sizeof(ngx_peer_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }

        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        u->naddrs = 1;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(u->port);
        sin->sin_addr.s_addr = in_addr;

        u->addrs[0].sockaddr = (struct sockaddr *) sin;
        u->addrs[0].socklen = sizeof(struct sockaddr_in);

        p = ngx_pnalloc(pool, u->host.len + sizeof(":65536") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        u->addrs[0].name.len = ngx_sprintf(p, "%V:%d", &u->host, u->port) - p;
        u->addrs[0].name.data = p;
    }

    return NGX_OK;
}
