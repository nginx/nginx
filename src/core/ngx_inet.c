
#include <ngx_config.h>
#include <ngx_core.h>


/* AF_INET only */

size_t ngx_sock_ntop(int family, struct sockaddr *addr, char *text, size_t len)
{
    char                *p;
    struct sockaddr_in  *addr_in;

    if (family != AF_INET) {
        return 0;
    }

    addr_in = (struct sockaddr_in *) addr;
    p = (char *) &addr_in->sin_addr;

    return ngx_snprintf(text, len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u",
                        (unsigned char) p[0],
                        (unsigned char) p[1],
                        (unsigned char) p[2],
                        (unsigned char) p[3]);
}


size_t ngx_inet_ntop(int family, char *addr, char *text, size_t len)
{
    if (family != AF_INET) {
        return 0;
    }

    return ngx_snprintf(text, len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u",
                        (unsigned char) addr[0],
                        (unsigned char) addr[1],
                        (unsigned char) addr[2],
                        (unsigned char) addr[3]);
}
