
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_max_sockets;


ngx_os_io_t ngx_os_io = {
    ngx_wsarecv,
    NULL,
    NULL,
    NULL
};


/* Should these pointers be per protocol ? */
LPFN_ACCEPTEX              acceptex;
LPFN_GETACCEPTEXSOCKADDRS  getacceptexsockaddrs;
LPFN_TRANSMITFILE          transmitfile;

static GUID ae_guid = WSAID_ACCEPTEX;
static GUID as_guid = WSAID_GETACCEPTEXSOCKADDRS;
static GUID tf_guid = WSAID_TRANSMITFILE;


int ngx_os_init(ngx_log_t *log)
{
    u_int            sp;
    DWORD            bytes;
    SOCKET           s;
    WSADATA          wsd;
    OSVERSIONINFOEX  osvi;

    /* get Windows version */

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    osviex = GetVersionEx((OSVERSIONINFO *) &osvi);

    if (osviex == 0) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (GetVersionEx((OSVERSIONINFO *) &osvi) == 0)
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "GetVersionEx() failed");
            return NGX_ERROR;
        }
    }

    /*
     *  Windows 95       1400
     *  Windows 98       1410
     *  Windows ME       1490
     *  Windows NT 3.51  2351
     *  Windows NT 4.0   2400
     *  Windows 2000     2500
     *  Windows XP       2501
     *  Windows 2003     2502
     */

    ngx_win32_version = osvi.dwPlatformId * 1000
                        + osvi.dwMajorVersion * 100
                        + osvi.dwMinorVersion;

    if (osviex) {
        sp = osvi.wServicePackMajor * 100 + osvi.wServicePackMinor;

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "OS: %u build:%u, %s, SP:%u, suite:%x, type:%u",
                      ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
                      sp, osvi.wSuiteMask, osvi.wProductType);

    } else {
        ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %u build:%u, %s",
                      ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion);
    }


    /* init Winsock */

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAStartup() failed");
        return NGX_ERROR;
    }

    /* get AcceptEx(), GetAcceptExSockAddrs() and TransmitFile() addresses */

    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, 0);
    if (s == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      ngx_socket_n " %s falied");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &ae_guid, sizeof(GUID),
                 &acceptex, sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL) == -1) {

        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_ACCEPTEX) failed");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &as_guid, sizeof(GUID),
                 &getacceptexsockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
                 &bytes, NULL, NULL) == -1) {

        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_ACCEPTEX) failed");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tf_guid, sizeof(GUID),
                 &transmitfile, sizeof(LPFN_TRANSMITFILE), &bytes,
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
