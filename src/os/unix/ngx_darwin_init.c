
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


char    ngx_darwin_kern_ostype[16];
char    ngx_darwin_kern_osrelease[128];
int     ngx_darwin_hw_ncpu;
int     ngx_darwin_kern_ipc_somaxconn;
u_long  ngx_darwin_net_inet_tcp_sendspace;

ngx_uint_t  ngx_debug_malloc;


static ngx_os_io_t ngx_darwin_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
#if (NGX_HAVE_SENDFILE)
    ngx_darwin_sendfile_chain,
    NGX_IO_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


typedef struct {
    char        *name;
    void        *value;
    size_t       size;
    ngx_uint_t   exists;
} sysctl_t;


sysctl_t sysctls[] = {
    { "hw.ncpu",
      &ngx_darwin_hw_ncpu,
      sizeof(ngx_darwin_hw_ncpu), 0 },

    { "net.inet.tcp.sendspace",
      &ngx_darwin_net_inet_tcp_sendspace,
      sizeof(ngx_darwin_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &ngx_darwin_kern_ipc_somaxconn,
      sizeof(ngx_darwin_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
ngx_debug_init()
{
#if (NGX_DEBUG_MALLOC)

    /*
     * MacOSX 10.6, 10.7:  MallocScribble fills freed memory with 0x55
     *                     and fills allocated memory with 0xAA.
     * MacOSX 10.4, 10.5:  MallocScribble fills freed memory with 0x55,
     *                     MallocPreScribble fills allocated memory with 0xAA.
     * MacOSX 10.3:        MallocScribble fills freed memory with 0x55,
     *                     and no way to fill allocated memory.
     */

    setenv("MallocScribble", "1", 0);

    ngx_debug_malloc = 1;

#else

    if (getenv("MallocScribble")) {
        ngx_debug_malloc = 1;
    }

#endif
}


ngx_int_t
ngx_os_specific_init(ngx_log_t *log)
{
    size_t      size;
    ngx_err_t   err;
    ngx_uint_t  i;

    size = sizeof(ngx_darwin_kern_ostype);
    if (sysctlbyname("kern.ostype", ngx_darwin_kern_ostype, &size, NULL, 0)
        == -1)
    {
        err = ngx_errno;

        if (err != NGX_ENOENT) {

            ngx_log_error(NGX_LOG_ALERT, log, err,
                          "sysctlbyname(kern.ostype) failed");

            if (err != NGX_ENOMEM) {
                return NGX_ERROR;
            }

            ngx_darwin_kern_ostype[size - 1] = '\0';
        }
    }

    size = sizeof(ngx_darwin_kern_osrelease);
    if (sysctlbyname("kern.osrelease", ngx_darwin_kern_osrelease, &size,
                     NULL, 0)
        == -1)
    {
        err = ngx_errno;

        if (err != NGX_ENOENT) {

            ngx_log_error(NGX_LOG_ALERT, log, err,
                          "sysctlbyname(kern.osrelease) failed");

            if (err != NGX_ENOMEM) {
                return NGX_ERROR;
            }

            ngx_darwin_kern_osrelease[size - 1] = '\0';
        }
    }

    for (i = 0; sysctls[i].name; i++) {
        size = sysctls[i].size;

        if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
            == 0)
        {
            sysctls[i].exists = 1;
            continue;
        }

        err = ngx_errno;

        if (err == NGX_ENOENT) {
            continue;
        }

        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "sysctlbyname(%s) failed", sysctls[i].name);
        return NGX_ERROR;
    }

    ngx_ncpu = ngx_darwin_hw_ncpu;

    if (ngx_darwin_kern_ipc_somaxconn > 32767) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return NGX_ERROR;
    }

    ngx_tcp_nodelay_and_tcp_nopush = 1;

    ngx_os_io = ngx_darwin_io;

    return NGX_OK;
}


void
ngx_os_specific_status(ngx_log_t *log)
{
    u_long      value;
    ngx_uint_t  i;

    if (ngx_darwin_kern_ostype[0]) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
                      ngx_darwin_kern_ostype, ngx_darwin_kern_osrelease);
    }

    for (i = 0; sysctls[i].name; i++) {
        if (sysctls[i].exists) {
            if (sysctls[i].size == sizeof(long)) {
                value = *(long *) sysctls[i].value;

            } else {
                value = *(int *) sysctls[i].value;
            }

            ngx_log_error(NGX_LOG_NOTICE, log, 0, "%s: %l",
                          sysctls[i].name, value);
        }
    }
}
