#include <nxg_config.h>

#include <nxg_log.h>
#include <nxg_errno.h>
#include <nxg_socket.h>


void ngx_init_sockets(ngx_log_t *log)
{
    WSADATA  wsd;

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "ngx_init_sockets: WSAStartup failed");
}

int ngx_nonblocking(ngx_socket_t s)
{
    unsigned long  nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}
