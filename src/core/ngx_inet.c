
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * ngx_sock_ntop() and ngx_inet_ntop() may be implemented as
 * "ngx_sprintf(text, "%ud.%ud.%ud.%ud", p[0], p[1], p[2], p[3])", however,
 * they had been implemented long before the ngx_sprintf() had appeared
 * and they are faster by 1.5-2.5 times, so it is worth to keep them.
 *
 * By the way, the implementation using ngx_sprintf() is faster by 2.5-3 times
 * than using FreeBSD libc's snprintf().
 */


static ngx_inline size_t
ngx_sprint_uchar(u_char *text, u_char c, size_t len)
{
    size_t      n;
    ngx_uint_t  c1, c2;

    n = 0;

    if (len == n) {
        return n;
    }

    c1 = c / 100;

    if (c1) {
        *text++ = (u_char) (c1 + '0');
        n++;

        if (len == n) {
            return n;
        }
    }

    c2 = (c % 100) / 10;

    if (c1 || c2) {
        *text++ = (u_char) (c2 + '0');
        n++;

        if (len == n) {
            return n;
        }
    }

    c2 = c % 10;

    *text++ = (u_char) (c2 + '0');
    n++;

    return n;
}


/* AF_INET only */

size_t
ngx_sock_ntop(int family, struct sockaddr *sa, u_char *text, size_t len)
{
    u_char              *p;
    size_t               n;
    ngx_uint_t           i;
    struct sockaddr_in  *sin;

    if (len == 0) {
        return 0;
    }

    if (family != AF_INET) {
        return 0;
    }

    sin = (struct sockaddr_in *) sa;
    p = (u_char *) &sin->sin_addr;

    if (len > INET_ADDRSTRLEN) {
        len = INET_ADDRSTRLEN;
    }

    n = ngx_sprint_uchar(text, p[0], len);

    i = 1;

    do {
        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        text[n++] = '.';

        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        n += ngx_sprint_uchar(&text[n], p[i++], len - n);

    } while (i < 4);

    if (len == n) {
        text[n] = '\0';
        return n;
    }

    text[n] = '\0';

    return n;
}

size_t
ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    u_char      *p;
    size_t       n;
    ngx_uint_t   i;

    if (len == 0) {
        return 0;
    }

    if (family != AF_INET) {
        return 0;
    }

    p = (u_char *) addr;

    if (len > INET_ADDRSTRLEN) {
        len = INET_ADDRSTRLEN;
    }

    n = ngx_sprint_uchar(text, p[0], len);

    i = 1;

    do {
        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        text[n++] = '.';

        if (len == n) {
            text[n - 1] = '\0';
            return n;
        }

        n += ngx_sprint_uchar(&text[n], p[i++], len - n);

    } while (i < 4);

    if (len == n) {
        text[n] = '\0';
        return n;
    }

    text[n] = '\0';

    return n;
}


/* AF_INET only */

ngx_int_t
ngx_ptocidr(ngx_str_t *text, void *cidr)
{
    ngx_int_t         m;
    ngx_uint_t        i;
    ngx_inet_cidr_t  *in_cidr;

    in_cidr = cidr;

    for (i = 0; i < text->len; i++) {
        if (text->data[i] == '/') {
            break;
        }
    }

    if (i == text->len) {
        return NGX_ERROR;
    }

    text->data[i] = '\0';
    in_cidr->addr = inet_addr((char *) text->data);
    text->data[i] = '/';
    if (in_cidr->addr == INADDR_NONE) {
        return NGX_ERROR;
    }

    m = ngx_atoi(&text->data[i + 1], text->len - (i + 1));
    if (m == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (m == 0) {

        /* the x86 compilers use the shl instruction that shifts by modulo 32 */

        in_cidr->mask = 0;
        return NGX_OK;
    }

    in_cidr->mask = htonl((ngx_uint_t) (0 - (1 << (32 - m))));

    if (in_cidr->addr == (in_cidr->addr & in_cidr->mask)) {
        return NGX_OK;
    }

    in_cidr->addr &= in_cidr->mask;

    return NGX_DONE;
}


ngx_int_t
ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u)
{
    u_char              *p, *host, *port_start;
    size_t               len, port_len;
    ngx_int_t            port;
    ngx_uint_t           i;
    struct hostent      *h;
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un  *saun;
#endif

    len = u->url.len;
    p = u->url.data;

    if (ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {

#if (NGX_HAVE_UNIX_DOMAIN)

        p += 5;
        len -= 5;

        u->uri.len = len;
        u->uri.data = p;

        if (u->uri_part) {
            for (i = 0; i < len; i++) {

                if (p[i] == ':') {
                    len = i;

                    u->uri.len -= len + 1;
                    u->uri.data += len + 1;

                    break;
                }
            }
        }

        if (len == 0) {
            u->err = "no path in the unix domain socket";
            return NGX_ERROR;
        }

        if (len + 1 > sizeof(saun->sun_path)) {
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
        (void) ngx_cpystrn((u_char *) saun->sun_path, p, len + 1);

        u->addrs[0].sockaddr = (struct sockaddr *) saun;
        u->addrs[0].socklen = sizeof(struct sockaddr_un);
        u->addrs[0].name.len = len + 5;
        u->addrs[0].name.data = u->url.data;

        u->host.len = len;
        u->host.data = p;

        u->unix_socket = 1;

        return NGX_OK;

#else
        u->err = "the unix domain sockets are not supported on this platform";

        return NGX_ERROR;

#endif
    }

    if ((p[0] == ':' || p[0] == '/') && !u->listen) {
        u->err = "invalid host";
        return NGX_ERROR;
    }

    u->host.data = p;

    port_start = NULL;
    port_len = 0;

    for (i = 0; i < len; i++) {

        if (p[i] == ':') {
            port_start = &p[i + 1];
            u->host.len = i;

            if (!u->uri_part) {
                port_len = len - (i + 1);
                break;
            }
        }

        if (p[i] == '/') {
            u->uri.len = len - i;
            u->uri.data = &p[i];

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (port_start == NULL) {
                u->no_port = 1;
                goto no_port;
            }

            port_len = &p[i] - port_start;

            if (port_len == 0) {
                u->err = "invalid port";
                return NGX_ERROR;
            }

            break;
        }
    }

    if (port_start) {

        if (port_len == 0) {
            port_len = &p[i] - port_start;

            if (port_len == 0) {
                u->err = "invalid port";
                return NGX_ERROR;
            }
        }

        port = ngx_atoi(port_start, port_len);

        if (port == NGX_ERROR || port < 1 || port > 65536) {
            u->err = "invalid port";
            return NGX_ERROR;
        }

    } else {
        port = ngx_atoi(p, len);

        if (port == NGX_ERROR) {
            u->host.len = len;
            u->no_port = 1;

            goto no_port;
        }

        u->wildcard = 1;
    }

    u->port = (in_port_t) port;

no_port:

    if (u->listen) {

        if (u->port == 0) {
            if (u->default_port == 0) {
                u->err = "no port";
                return NGX_ERROR;
            }

            u->port = u->default_port;
        }

        if (u->host.len == 1 && u->host.data[0] == '*') {
            u->host.len = 0;
        }

        /* AF_INET only */

        if (u->host.len) {

            host = ngx_alloc(u->host.len + 1, pool->log);
            if (host == NULL) {
                return NGX_ERROR;
            }

            (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);

            u->addr.in_addr = inet_addr((const char *) host);

            if (u->addr.in_addr == INADDR_NONE) {
                h = gethostbyname((const char *) host);

                if (h == NULL || h->h_addr_list[0] == NULL) {
                    ngx_free(host);
                    u->err = "host not found";
                    return NGX_ERROR;
                }

                u->addr.in_addr = *(in_addr_t *) (h->h_addr_list[0]);
            }

            ngx_free(host);

        } else {
            u->addr.in_addr = INADDR_ANY;
        }

        return NGX_OK;
    }

    if (u->host.len == 0) {
        u->err = "no host";
        return NGX_ERROR;
    }

    if (u->no_resolve) {
        return NGX_OK;
    }

    if (u->no_port) {
        u->port = u->default_port;
    }

    if (u->port == 0) {
        u->err = "no port";
        return NGX_ERROR;
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

            len = INET_ADDRSTRLEN - 1 + 1 + sizeof(":65536") - 1;

            p = ngx_palloc(pool, len);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_sock_ntop(AF_INET, (struct sockaddr *) sin, p, len);

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

        p = ngx_palloc(pool, u->host.len + sizeof(":65536") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        u->addrs[0].name.len = ngx_sprintf(p, "%V:%d", &u->host, u->port) - p;
        u->addrs[0].name.data = p;
    }

    return NGX_OK;
}
