
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


ngx_uint_t  ngx_win32_version;
ngx_uint_t  ngx_ncpu;
ngx_uint_t  ngx_max_wsabufs;
ngx_int_t   ngx_max_sockets;
ngx_uint_t  ngx_inherited_nonblocking = 1;
ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;

char        ngx_unique[NGX_INT32_LEN + 1];


ngx_os_io_t ngx_os_io = {
    ngx_wsarecv,
    ngx_wsarecv_chain,
    ngx_udp_wsarecv,
    ngx_wsasend,
    ngx_wsasend_chain,
    0
};


typedef struct {
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType;
} ngx_osviex_stub_t;


static u_int               osviex;
static OSVERSIONINFOEX     osvi;

/* Should these pointers be per protocol ? */
LPFN_ACCEPTEX              ngx_acceptex;
LPFN_GETACCEPTEXSOCKADDRS  ngx_getacceptexsockaddrs;
LPFN_TRANSMITFILE          ngx_transmitfile;
LPFN_TRANSMITPACKETS       ngx_transmitpackets;
LPFN_CONNECTEX             ngx_connectex;
LPFN_DISCONNECTEX          ngx_disconnectex;

static GUID ax_guid = WSAID_ACCEPTEX;
static GUID as_guid = WSAID_GETACCEPTEXSOCKADDRS;
static GUID tf_guid = WSAID_TRANSMITFILE;
static GUID tp_guid = WSAID_TRANSMITPACKETS;
static GUID cx_guid = WSAID_CONNECTEX;
static GUID dx_guid = WSAID_DISCONNECTEX;


ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    DWORD        bytes;
    SOCKET       s;
    WSADATA      wsd;
    ngx_err_t    err;
    ngx_uint_t   n;
    SYSTEM_INFO  si;

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
     *  Windows Vista/2008   260000
     *
     *  Windows CE x.x       3xxxxx
     */

    ngx_win32_version = osvi.dwPlatformId * 100000
                        + osvi.dwMajorVersion * 10000
                        + osvi.dwMinorVersion * 100;

    if (osviex) {
        ngx_win32_version += osvi.wServicePackMajor * 10
                             + osvi.wServicePackMinor;
    }

    GetSystemInfo(&si);
    ngx_pagesize = si.dwPageSize;
    ngx_ncpu = si.dwNumberOfProcessors;
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }

    /* delete default "C" locale for _wcsicmp() */
    setlocale(LC_ALL, "");


    /* init Winsock */

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "WSAStartup() failed");
        return NGX_ERROR;
    }

    if (ngx_win32_version < NGX_WIN_NT) {
        ngx_max_wsabufs = 16;
        return NGX_OK;
    }

    /* STUB: ngx_uint_t max */
    ngx_max_wsabufs = 1024 * 1024;

    /*
     * get AcceptEx(), GetAcceptExSockAddrs(), TransmitFile(),
     * TransmitPackets(), ConnectEx(), and DisconnectEx() addresses
     */

    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      ngx_socket_n " falied");
        return NGX_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &ax_guid, sizeof(GUID),
                 &ngx_acceptex, sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL)
        == -1)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_ACCEPTEX) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &as_guid, sizeof(GUID),
                 &ngx_getacceptexsockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
                 &bytes, NULL, NULL)
        == -1)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_GETACCEPTEXSOCKADDRS) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tf_guid, sizeof(GUID),
                 &ngx_transmitfile, sizeof(LPFN_TRANSMITFILE), &bytes,
                 NULL, NULL)
        == -1)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_TRANSMITFILE) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tp_guid, sizeof(GUID),
                 &ngx_transmitpackets, sizeof(LPFN_TRANSMITPACKETS), &bytes,
                 NULL, NULL)
        == -1)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_TRANSMITPACKETS) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &cx_guid, sizeof(GUID),
                 &ngx_connectex, sizeof(LPFN_CONNECTEX), &bytes,
                 NULL, NULL)
        == -1)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_CONNECTEX) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &dx_guid, sizeof(GUID),
                 &ngx_disconnectex, sizeof(LPFN_DISCONNECTEX), &bytes,
                 NULL, NULL)
        == -1)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_DISCONNECTEX) failed");
    }

    if (ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    if (GetEnvironmentVariable("ngx_unique", ngx_unique, NGX_INT32_LEN + 1)
        != 0)
    {
        ngx_process = NGX_PROCESS_WORKER;

    } else {
        err = ngx_errno;

        if (err != ERROR_ENVVAR_NOT_FOUND) {
            ngx_log_error(NGX_LOG_EMERG, log, err,
                          "GetEnvironmentVariable(\"ngx_unique\") failed");
            return NGX_ERROR;
        }

        ngx_sprintf((u_char *) ngx_unique, "%P%Z", ngx_pid);
    }

    srand((unsigned) ngx_time());

    return NGX_OK;
}


void
ngx_os_status(ngx_log_t *log)
{
    ngx_osviex_stub_t  *osviex_stub;

    ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER);

    if (osviex) {

        /*
         * the MSVC 6.0 SP2 defines wSuiteMask and wProductType
         * as WORD wReserved[2]
         */
        osviex_stub = (ngx_osviex_stub_t *) &osvi.wServicePackMinor;

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "OS: %ud build:%ud, \"%s\", suite:%Xd, type:%ud",
                      ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
                      osviex_stub->wSuiteMask, osviex_stub->wProductType);

    } else {
        if (osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {

            /* Win9x build */

            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "OS: %u build:%ud.%ud.%ud, \"%s\"",
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

            ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %ud build:%ud, \"%s\"",
                          ngx_win32_version, osvi.dwBuildNumber,
                          osvi.szCSDVersion);
        }
    }
}
