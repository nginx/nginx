
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_win32_version;
int  ngx_max_sockets;
int  ngx_inherited_nonblocking = 1;


ngx_os_io_t ngx_os_io = {
    ngx_wsarecv,
    NULL,
    NULL,
    ngx_wsasend_chain,
    0
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
    u_int            osviex;
    DWORD            bytes;
    SOCKET           s;
    WSADATA          wsd;
    OSVERSIONINFOEX  osvi;

    /* get Windows version */

    ngx_memzero(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    osviex = GetVersionEx((OSVERSIONINFO *) &osvi);

    if (osviex == 0) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (GetVersionEx((OSVERSIONINFO *) &osvi) == 0) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "GetVersionEx() failed");
            return NGX_ERROR;
        }
    }

    /*
     *  Windows 95           140000
     *  Windows 98           141000
     *  Windows ME           149000
     *  Windows NT 3.51      235100
     *  Windows NT 4.0       240000
     *  Windows NT 4.0 SP5   240050
     *  Windows 2000         250000
     *  Windows XP           250100
     *  Windows 2003         250200
     */

    ngx_win32_version = osvi.dwPlatformId * 100000
                        + osvi.dwMajorVersion * 10000
                        + osvi.dwMinorVersion * 100;

    if (osviex) {
        ngx_win32_version += osvi.wServicePackMajor * 10
                             + osvi.wServicePackMinor;

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "OS: %u build:%u, \"%s\", suite:%x, type:%u",
                      ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
                      osvi.wReserved[0], osvi.wReserved[1]);

#if 0
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "OS: %u build:%u, \"%s\", suite:%x, type:%u",
                      ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
                      osvi.wSuiteMask, osvi.wProductType);
#endif

    } else {
        if (osvi.dwPlatformId == 1) {

            /* Win9x build */

            ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %u build:%u.%u.%u, \"%s\"",
                          ngx_win32_version,
                          osvi.dwBuildNumber >> 24,
                          (osvi.dwBuildNumber >> 16) & 0xff,
                          osvi.dwBuildNumber & 0xffff,
                          osvi.szCSDVersion);

        } else {
            ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %u build:%u, \"%s\"",
                          ngx_win32_version, osvi.dwBuildNumber,
                          osvi.szCSDVersion);
        }
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
