
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_log.h>
#include <ngx_errno.h>
#include <ngx_socket.h>


/* These pointers should be per protocol ? */
LPFN_ACCEPTEX              AcceptEx;
LPFN_GETACCEPTEXSOCKADDRS  GetAcceptExSockaddrs;
LPFN_TRANSMITFILE          TransmitFile;

static GUID ae_guid = WSAID_ACCEPTEX;
static GUID as_guid = WSAID_GETACCEPTEXSOCKADDRS;
static GUID tf_guid = WSAID_TRANSMITFILE;


int ngx_init_sockets(ngx_log_t *log)
{
    DWORD    bytes;
    SOCKET   s;
    WSADATA  wsd;

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAStartup failed");
        return NGX_ERROR;
    }

    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, 0);
    if (s == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      ngx_socket_n " %s falied");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &ae_guid, sizeof(GUID),
                 &AcceptEx, sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL) == -1) {

        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_ACCEPTEX) failed");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &as_guid, sizeof(GUID),
                 &GetAcceptExSockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
                 &bytes, NULL, NULL) == -1) {

        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_ACCEPTEX) failed");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tf_guid, sizeof(GUID),
                 &TransmitFile, sizeof(LPFN_TRANSMITFILE), &bytes,
                                                           NULL, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_TRANSMITFILE) failed");
        return NGX_ERROR;
    }

    if (ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    return NGX_OK;
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
