
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_uint_t  ngx_win32_version;
ngx_uint_t  ngx_ncpu;
ngx_int_t   ngx_max_sockets;
ngx_uint_t  ngx_inherited_nonblocking = 1;
ngx_fd_t    ngx_stderr_fileno;


ngx_os_io_t ngx_os_io = {
    ngx_wsarecv,
    ngx_wsarecv_chain,
    NULL,
    ngx_wsasend_chain,
    0
};


typedef struct {
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType;
} ngx_osviex_stub_t;


/* Should these pointers be per protocol ? */
LPFN_ACCEPTEX              acceptex;
LPFN_GETACCEPTEXSOCKADDRS  getacceptexsockaddrs;
LPFN_TRANSMITFILE          transmitfile;

static GUID ae_guid = WSAID_ACCEPTEX;
static GUID as_guid = WSAID_GETACCEPTEXSOCKADDRS;
static GUID tf_guid = WSAID_TRANSMITFILE;


ngx_int_t ngx_os_init(ngx_log_t *log)
{
    u_int               osviex;
    DWORD               bytes;
    SOCKET              s;
    WSADATA             wsd;
    SYSTEM_INFO         si;
    OSVERSIONINFOEX     osvi;
    ngx_osviex_stub_t  *osviex_stub;

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
     *  Windows 3.1 Win32s   0xxxxx
     *
     *  Windows 95           140000
     *  Windows 98           141000
     *  Windows ME           149000
     *  Windows NT 3.51      235100
     *  Windows NT 4.0       240000
     *  Windows NT 4.0 SP5   240050
     *  Windows 2000         250000
     *  Windows XP           250100
     *  Windows 2003         250200
     *
     *  Windows CE x.x       3xxxxx
     */

    ngx_win32_version = osvi.dwPlatformId * 100000
                        + osvi.dwMajorVersion * 10000
                        + osvi.dwMinorVersion * 100;

    if (osviex) {
        ngx_win32_version += osvi.wServicePackMajor * 10
                             + osvi.wServicePackMinor;

        /*
         * the MSVC 6.0 SP2 defines wSuiteMask and wProductType
         * as WORD wReserved[2]
         */
        osviex_stub = (ngx_osviex_stub_t *) &osvi.wServicePackMinor;

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "OS: %u build:%u, \"%s\", suite:%x, type:%u",
                      ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
                      osviex_stub->wSuiteMask, osviex_stub->wProductType);

    } else {
        if (osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {

            /* Win9x build */

            ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %u build:%u.%u.%u, \"%s\"",
                          ngx_win32_version,
                          osvi.dwBuildNumber >> 24,
                          (osvi.dwBuildNumber >> 16) & 0xff,
                          osvi.dwBuildNumber & 0xffff,
                          osvi.szCSDVersion);

        } else {

            /*
             * VER_PLATFORM_WIN32_NT
             *
             * we do not currently support VER_PLATFORM_WIN32_CE
             * and we do not support VER_PLATFORM_WIN32s at all
             */

            ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %u build:%u, \"%s\"",
                          ngx_win32_version, osvi.dwBuildNumber,
                          osvi.szCSDVersion);
        }
    }

    GetSystemInfo(&si);
    ngx_pagesize = si.dwPageSize;
    ngx_ncpu = si.dwNumberOfProcessors;


    /* init Winsock */

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAStartup() failed");
        return NGX_ERROR;
    }

    if (ngx_win32_version < NGX_WIN_NT) {
        return NGX_OK;
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


void ngx_os_status(ngx_log_t *log)
{
}
