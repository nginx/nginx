
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
