
/*
 * Copyright (C) Igor Sysoev
 */



#include <ngx_config.h>
#include <ngx_core.h>


ngx_inline static size_t ngx_sprint_uchar(u_char *text, u_char c, size_t len)
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

size_t ngx_sock_ntop(int family, struct sockaddr *addr, u_char *text,
                     size_t len)
{
    u_char              *p;
    size_t               n;
    ngx_uint_t           i;
    struct sockaddr_in  *addr_in;

    if (len == 0) {
        return 0;
    }

    if (family != AF_INET) {
        return 0;
    }

    addr_in = (struct sockaddr_in *) addr;
    p = (u_char *) &addr_in->sin_addr;

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

#if 0
    return ngx_snprintf((char *) text,
                        len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
#endif
}


size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
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

#if 0
    return ngx_snprintf((char *) text,
                        len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
#endif
}


/* AF_INET only */

ngx_int_t ngx_ptocidr(ngx_str_t *text, void *cidr)
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


#if 0

ngx_int_t ngx_inet_addr_port(ngx_conf_t *cf, ngx_command_t *cmd,
                             ngx_str_t *addr_port)
{
    u_char          *host;
    ngx_int_t        port;
    ngx_uint_t       p;
    struct hostent  *h;

    for (p = 0; p < addr_port->len; p++) {
        if (addr_port->data[p] == ':') {
            break;
        }
    }

    in_addr->host.len = p;
    if (!(in_addr->host.data = ngx_palloc(pool, p + 1))) {
        return NGX_ERROR;
    }

    ngx_cpystrn(in_addr->host.data, addr_port->data, p + 1);

    if (p == addr_port->len) {
        p = 0;
    }

    port = ngx_atoi(&addr[p], args[1].len - p);
    if (port == NGX_ERROR && p == 0) {

        /* default port */
        iap->port = 0;

    } else if ((port == NGX_ERROR && p != 0) /* "listen host:NONNUMBER" */
               || (port < 1 || port > 65536)) { /* "listen 99999" */

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid port \"%s\" in \"%s\" directive, "
                           "it must be a number between 1 and 65535",
                           &addr[p], cmd->name.data);

        return NGX_CONF_ERROR;

    } else if (p == 0) {
        ls->addr = INADDR_ANY;
        ls->port = (in_port_t) port;
        return NGX_CONF_OK;
    }

    return NGX_OK;
}

#endif
