#include <ngx_config.h>

#include <ngx_log.h>
#include <ngx_errno.h>
#include <ngx_socket.h>


void ngx_init_sockets(ngx_log_t *log)
{
    WSADATA  wsd;

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "ngx_init_sockets: WSAStartup failed");

    /* get AcceptEx(), TransmitFile() functions */
}

int ngx_nonblocking(ngx_socket_t s)
{
    unsigned long  nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}

int ngx_blocking(ngx_socket_t s)
{
    unsigned long  nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}
