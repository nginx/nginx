
#include <ngx_config.h>
#include <ngx_core.h>


/* AF_INET only */

size_t ngx_sock_ntop(int family, struct sockaddr *addr, u_char *text,
                     size_t len)
{
    u_char              *p;
    struct sockaddr_in  *addr_in;

    if (family != AF_INET) {
        return 0;
    }

    addr_in = (struct sockaddr_in *) addr;
    p = (u_char *) &addr_in->sin_addr;

    return ngx_snprintf((char *) text,
                        len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}


size_t ngx_inet_ntop(int family, u_char *addr, u_char *text, size_t len)
{
    if (family != AF_INET) {
        return 0;
    }

    return ngx_snprintf((char *) text,
                        len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}
