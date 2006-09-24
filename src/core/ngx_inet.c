
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


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

    return NGX_OK;
}


ngx_int_t
ngx_parse_url(ngx_conf_t *cf, ngx_url_t *u)
{
    u_char              *p;
    size_t               len;
    ngx_int_t            port;
    ngx_uint_t           i;
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un  *saun;
#endif

    len = u->url.len;
    p = u->url.data;

    if (ngx_strncasecmp(p, "unix:", 5) == 0) {

#if (NGX_HAVE_UNIX_DOMAIN)

        u->type = NGX_PARSE_URL_UNIX;
        u->uri = u->url;

        p += 5;
        len -= 5;

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

        u->peers = ngx_pcalloc(cf->pool, sizeof(ngx_peers_t));
        if (u->peers == NULL) {
            return NGX_ERROR;
        }

        saun = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_un));
        if (saun == NULL) {
            return NGX_ERROR;
        }

        u->peers->number = 1;

        saun->sun_family = AF_UNIX;
        (void) ngx_cpystrn((u_char *) saun->sun_path, p, len + 1);

        u->peers->peer[0].sockaddr = (struct sockaddr *) saun;
        u->peers->peer[0].socklen = sizeof(struct sockaddr_un);
        u->peers->peer[0].name = u->url;
        u->peers->peer[0].uri_separator = ":";

        u->host_header.len = sizeof("localhost") - 1;
        u->host_header.data = (u_char *) "localhost";

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

    u->type = NGX_PARSE_URL_INET;

    u->host.data = p;
    u->host_header.len = len;
    u->host_header.data = p;

    for (i = 0; i < len; i++) {

        if (p[i] == ':') {
            u->port.data = &p[i + 1];
            u->host.len = i;

            if (!u->uri_part) {
                u->port.len = &p[len] - u->port.data;
                break;
            }
        }

        if (p[i] == '/') {
            u->uri.len = len - i;
            u->uri.data = &p[i];
            u->host_header.len = i;

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (u->port.data == NULL) {
                u->default_port = 1;
                goto port;
            }

            u->port.len = &p[i] - u->port.data;

            if (u->port.len == 0) {
                u->err = "invalid port";
                return NGX_ERROR;
            }

            break;
        }
    }

    if (u->port.data) {

        if (u->port.len == 0) {
            u->port.len = &p[i] - u->port.data;

            if (u->port.len == 0) {
                u->err = "invalid port";
                return NGX_ERROR;
            }
        }

        port = ngx_atoi(u->port.data, u->port.len);

        if (port == NGX_ERROR || port < 1 || port > 65536) {
            u->err = "invalid port";
            return NGX_ERROR;
        }

    } else {
        port = ngx_atoi(p, len);

        if (port == NGX_ERROR) {
            u->default_port = 1;
            u->host.len = len;

            goto port;
        }

        u->port.len = len;
        u->port.data = p;
        u->wildcard = 1;
    }

    u->portn = (in_port_t) port;

port:

    if (u->listen) {
        return NGX_OK;
    }

    if (u->default_port) {

        if (u->upstream) {
            return NGX_OK;
        }

        if (u->default_portn == 0) {
            u->err = "no port";
            return NGX_ERROR;
        }

        u->portn = u->default_portn;

        u->port.data = ngx_palloc(cf->pool, sizeof("65536") - 1);
        if (u->port.data == NULL) {
            return NGX_ERROR;
        }

        u->port.len = ngx_sprintf(u->port.data, "%d", u->portn) - u->port.data;

    } else if (u->portn) {
        if (u->portn == u->default_portn) {
            u->default_port = 1;
        }

    } else {
        u->err = "no port";
        return NGX_ERROR;
    }

    if (u->host.len == 0) {
        u->err = "no host";
        return NGX_ERROR;
    }

    u->peers = ngx_inet_resolve_peer(cf, &u->host, u->portn);

    if (u->peers == NULL) {
        return NGX_ERROR;
    }

    if (u->peers == NGX_CONF_ERROR) {
        u->err = "host not found";
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_peers_t *
ngx_inet_resolve_peer(ngx_conf_t *cf, ngx_str_t *name, in_port_t port)
{
    u_char              *host;
    size_t               len;
    in_addr_t            in_addr;
    ngx_uint_t           i;
    ngx_peers_t         *peers;
    struct hostent      *h;
    struct sockaddr_in  *sin;

    host = ngx_palloc(cf->temp_pool, name->len + 1);
    if (host == NULL) {
        return NULL;
    }

    (void) ngx_cpystrn(host, name->data, name->len + 1);

    /* AF_INET only */

    in_addr = inet_addr((char *) host);

    if (in_addr == INADDR_NONE) {
        h = gethostbyname((char *) host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        /* MP: ngx_shared_palloc() */

        peers = ngx_pcalloc(cf->pool,
                            sizeof(ngx_peers_t) + sizeof(ngx_peer_t) * (i - 1));
        if (peers == NULL) {
            return NULL;
        }

        peers->number = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {

            sin = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NULL;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = htons(port);
            sin->sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);

            peers->peer[i].sockaddr = (struct sockaddr *) sin;
            peers->peer[i].socklen = sizeof(struct sockaddr_in);

            len = INET_ADDRSTRLEN - 1 + 1 + sizeof(":65536") - 1;

            peers->peer[i].name.data = ngx_palloc(cf->pool, len);
            if (peers->peer[i].name.data == NULL) {
                return NULL;
            }

            len = ngx_sock_ntop(AF_INET, (struct sockaddr *) sin,
                                peers->peer[i].name.data, len);

            peers->peer[i].name.len =
                                    ngx_sprintf(&peers->peer[i].name.data[len],
                                                ":%d", port)
                                      - peers->peer[i].name.data;

            peers->peer[i].uri_separator = "";

            peers->peer[i].weight = NGX_CONF_UNSET_UINT;
            peers->peer[i].max_fails = NGX_CONF_UNSET_UINT;
            peers->peer[i].fail_timeout = NGX_CONF_UNSET;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_peers_t));
        if (peers == NULL) {
            return NULL;
        }

        sin = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NULL;
        }

        peers->number = 1;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr.s_addr = in_addr;

        peers->peer[0].sockaddr = (struct sockaddr *) sin;
        peers->peer[0].socklen = sizeof(struct sockaddr_in);

        peers->peer[0].name.data = ngx_palloc(cf->pool,
                                              name->len + sizeof(":65536") - 1);
        if (peers->peer[0].name.data == NULL) {
            return NULL;
        }

        peers->peer[0].name.len = ngx_sprintf(peers->peer[0].name.data, "%V:%d",
                                              name, port)
                                  - peers->peer[0].name.data;

        peers->peer[0].uri_separator = "";
    }

    return peers;
}


ngx_peers_t *
ngx_inet_upstream_parse(ngx_conf_t *cf, ngx_inet_upstream_t *u)
{
    char                *err;
    u_char              *host;
    size_t               len;
    in_addr_t            in_addr;
    ngx_uint_t           i;
    ngx_peers_t         *peers;
    struct hostent      *h;
    struct sockaddr_in  *sin;

    err = ngx_inet_parse_host_port(u);

    if (err) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s in upstream \"%V\"", err, &u->name);
        return NULL;
    }

    if (u->default_port) {

        if (u->default_port_value == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "no port in upstream \"%V\"", &u->name);
            return NULL;
        }

        u->port = u->default_port_value;

        u->port_text.data = ngx_palloc(cf->pool, sizeof("65536") - 1);
        if (u->port_text.data == NULL) {
            return NULL;
        }

        u->port_text.len = ngx_sprintf(u->port_text.data, "%d",
                                       u->default_port_value)
                           - u->port_text.data;

    } else if (u->port) {
        if (u->port == u->default_port_value) {
            u->default_port = 1;
        }

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no port in upstream \"%V\"", &u->name);
        return NULL;
    }

    if (u->host.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no host in upstream \"%V\"", &u->name);
        return NULL;
    }

    u->port = htons(u->port);

    host = ngx_palloc(cf->temp_pool, u->host.len + 1);
    if (host == NULL) {
        return NULL;
    }

    (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);

    /* AF_INET only */

    in_addr = inet_addr((char *) host);

    if (in_addr == INADDR_NONE) {
        h = gethostbyname((char *) host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "host %s is not found in upstream \"%V\"",
                               host, &u->name);
            return NULL;
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        /* MP: ngx_shared_palloc() */

        peers = ngx_pcalloc(cf->pool,
                            sizeof(ngx_peers_t) + sizeof(ngx_peer_t) * (i - 1));
        if (peers == NULL) {
            return NULL;
        }

        peers->number = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {

            sin = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NULL;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = u->port;
            sin->sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);

            peers->peer[i].sockaddr = (struct sockaddr *) sin;
            peers->peer[i].socklen = sizeof(struct sockaddr_in);

            len = INET_ADDRSTRLEN - 1 + 1 + u->port_text.len;

            peers->peer[i].name.data = ngx_palloc(cf->pool, len);
            if (peers->peer[i].name.data == NULL) {
                return NULL;
            }

            len = ngx_sock_ntop(AF_INET, (struct sockaddr *) sin,
                                peers->peer[i].name.data, len);

            peers->peer[i].name.data[len++] = ':';

            ngx_memcpy(peers->peer[i].name.data + len,
                       u->port_text.data, u->port_text.len);

            peers->peer[i].name.len = len + u->port_text.len;

            peers->peer[i].uri_separator = "";

            peers->peer[i].weight = NGX_CONF_UNSET_UINT;
            peers->peer[i].max_fails = NGX_CONF_UNSET_UINT;
            peers->peer[i].fail_timeout = NGX_CONF_UNSET;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_peers_t));
        if (peers == NULL) {
            return NULL;
        }

        sin = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NULL;
        }

        peers->number = 1;

        sin->sin_family = AF_INET;
        sin->sin_port = u->port;
        sin->sin_addr.s_addr = in_addr;

        peers->peer[0].sockaddr = (struct sockaddr *) sin;
        peers->peer[0].socklen = sizeof(struct sockaddr_in);

        len = u->host.len + 1 + u->port_text.len;

        peers->peer[0].name.len = len;

        peers->peer[0].name.data = ngx_palloc(cf->pool, len);
        if (peers->peer[0].name.data == NULL) {
            return NULL;
        }

        len = u->host.len;

        ngx_memcpy(peers->peer[0].name.data, u->host.data, len);

        peers->peer[0].name.data[len++] = ':';

        ngx_memcpy(peers->peer[0].name.data + len,
                   u->port_text.data, u->port_text.len);

        peers->peer[0].uri_separator = "";
    }

    return peers;
}


char *
ngx_inet_parse_host_port(ngx_inet_upstream_t *u)
{
    size_t      i;
    ngx_int_t   port;
    ngx_str_t  *url;

    url = &u->url;

    if (u->port_only) {
        i = 0;

    } else {
        if (url->data[0] == ':' || url->data[0] == '/') {
            return "invalid host";
        }

        i = 1;
    }

    u->host.data = url->data;
    u->host_header = *url;

    for ( /* void */ ; i < url->len; i++) {

        if (url->data[i] == ':') {
            u->port_text.data = &url->data[i] + 1;
            u->host.len = i;

            if (!u->uri_part) {
                u->port_text.len = &url->data[url->len] - u->port_text.data;
                break;
            }
        }

        if (url->data[i] == '/') {
            u->uri.data = &url->data[i];
            u->uri.len = url->len - i;
            u->host_header.len = i;

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (u->port_text.data == NULL) {
                u->default_port = 1;
                return NULL;
            }

            u->port_text.len = &url->data[i] - u->port_text.data;

            if (u->port_text.len == 0) {
                return "invalid port";
            }

            break;
        }
    }

    if (u->port_text.data) {

        if (u->port_text.len == 0) {
            u->port_text.len = &url->data[i] - u->port_text.data;

            if (u->port_text.len == 0) {
                return "invalid port";
            }
        }

        port = ngx_atoi(u->port_text.data, u->port_text.len);

        if (port == NGX_ERROR || port < 1 || port > 65536) {
            return "invalid port";
        }

    } else {
        port = ngx_atoi(url->data, url->len);

        if (port == NGX_ERROR) {
            u->default_port = 1;
            u->host.len = url->len;

            return NULL;
        }

        u->port_text = *url;
        u->wildcard = 1;
    }

    u->port = (in_port_t) port;

    return NULL;
}
