
#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_listen.h>

ngx_socket_t ngx_listen(struct sockaddr *addr, int backlog,
                        ngx_log_t *log, char *addr_text)
{
    ngx_socket_t   s;
    int            reuseaddr = 1;
#if (WIN32)
    unsigned long  nb = 1;
#endif

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno, "socket failed");

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(int)) == -1)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                     "ngx_listen: setsockopt (SO_REUSEADDR) failed");

#if (WIN32)
    if (ioctlsocket(s, FIONBIO, &nb) == -1)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                     "ngx_listen: ioctlsocket (FIONBIO) failed");
#else
    if (fcntl(s, F_SETFL, O_NONBLOCK) == -1)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                     "ngx_listen: fcntl (O_NONBLOCK) failed");
#endif

    if (bind(s, (struct sockaddr *) addr, sizeof(struct sockaddr_in)) == -1)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                     "ngx_listen: bind to %s failed", addr_text);

    if (listen(s, backlog) == -1)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                     "ngx_listen: listen to %s failed", addr_text);

    return s;
}
