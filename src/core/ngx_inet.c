
#include <ngx_config.h>
#include <ngx_string.h>
#include <ngx_inet.h>


size_t ngx_inet_ntop(int family, char *addr, char *text, size_t len)
{
    if (family != AF_INET)
        return 0;

    return ngx_snprintf(text, len > INET_ADDRSTRLEN ? INET_ADDRSTRLEN : len,
                        "%u.%u.%u.%u",
                        (unsigned char) addr[0],
                        (unsigned char) addr[1],
                        (unsigned char) addr[2],
                        (unsigned char) addr[3]);
}
