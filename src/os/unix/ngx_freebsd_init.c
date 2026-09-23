
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/* FreeBSD 3.0 at least */
char    ngx_freebsd_kern_ostype[16];
char    ngx_freebsd_kern_osrelease[128];
int     ngx_freebsd_kern_osreldate;
int     ngx_freebsd_hw_ncpu;
int     ngx_freebsd_kern_ipc_somaxconn;
u_long  ngx_freebsd_net_inet_tcp_sendspace;

/* FreeBSD 4.9 */
int     ngx_freebsd_machdep_hlt_logical_cpus;


ngx_uint_t  ngx_freebsd_use_tcp_nopush;

ngx_uint_t  ngx_debug_malloc;


static ngx_os_io_t ngx_freebsd_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
    ngx_udp_unix_send,
    ngx_udp_unix_sendmsg_chain,
#if (NGX_HAVE_SENDFILE)
    ngx_freebsd_sendfile_chain,
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
      &ngx_freebsd_hw_ncpu,
      sizeof(ngx_freebsd_hw_ncpu), 0 },

    { "machdep.hlt_logical_cpus",
      &ngx_freebsd_machdep_hlt_logical_cpus,
      sizeof(ngx_freebsd_machdep_hlt_logical_cpus), 0 },

    { "net.inet.tcp.sendspace",
      &ngx_freebsd_net_inet_tcp_sendspace,
      sizeof(ngx_freebsd_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &ngx_freebsd_kern_ipc_somaxconn,
      sizeof(ngx_freebsd_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
ngx_debug_init(void)
{
#if (NGX_DEBUG_MALLOC)

    ngx_debug_malloc = 1;

#else
    char  *mo;

    mo = getenv("MALLOC_OPTIONS");

    if (mo && ngx_strchr(mo, 'J')) {
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

    size = sizeof(ngx_freebsd_kern_ostype);
    if (sysctlbyname("kern.ostype",
                     ngx_freebsd_kern_ostype, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sysctlbyname(kern.ostype) failed");

        if (ngx_errno != NGX_ENOMEM) {
            return NGX_ERROR;
        }

        ngx_freebsd_kern_ostype[size - 1] = '\0';
    }

    size = sizeof(ngx_freebsd_kern_osrelease);
    if (sysctlbyname("kern.osrelease",
                     ngx_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sysctlbyname(kern.osrelease) failed");

        if (ngx_errno != NGX_ENOMEM) {
            return NGX_ERROR;
        }

        ngx_freebsd_kern_osrelease[size - 1] = '\0';
    }


    size = sizeof(int);
    if (sysctlbyname("kern.osreldate",
                     &ngx_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sysctlbyname(kern.osreldate) failed");
        return NGX_ERROR;
    }

    ngx_freebsd_use_tcp_nopush = 1;


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

    if (ngx_freebsd_machdep_hlt_logical_cpus) {
        ngx_ncpu = ngx_freebsd_hw_ncpu / 2;

    } else {
        ngx_ncpu = ngx_freebsd_hw_ncpu;
    }

    ngx_tcp_nodelay_and_tcp_nopush = 1;

    ngx_os_io = ngx_freebsd_io;

    return NGX_OK;
}


void
ngx_os_specific_status(ngx_log_t *log)
{
    u_long      value;
    ngx_uint_t  i;

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
                  ngx_freebsd_kern_ostype, ngx_freebsd_kern_osrelease);

#ifdef __DragonFly_version
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  ngx_freebsd_kern_osreldate, __DragonFly_version);
#else
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  ngx_freebsd_kern_osreldate, __FreeBSD_version);
#endif

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
