
#include <ngx_config.h>
#include <ngx_core.h>


/* FreeBSD 3.4 at least */
char ngx_freebsd_kern_ostype[20];
char ngx_freebsd_kern_osrelease[20];
int ngx_freebsd_kern_osreldate;
int ngx_freebsd_hw_ncpu;
int ngx_freebsd_net_inet_tcp_sendspace;
int ngx_freebsd_sendfile_nbytes_bug;
int ngx_freebsd_use_tcp_nopush;

/* FreeBSD 5.0 */
int ngx_freebsd_kern_ipc_zero_copy_send;


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    NULL,
#if (HAVE_SENDFILE)
    ngx_freebsd_sendfile_chain,
    NGX_HAVE_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


typedef struct {
    char    *name;
    int     *value;
    size_t   size;
} sysctl_t;


sysctl_t sysctls[] = {
    {"hw.ncpu",
     &ngx_freebsd_hw_ncpu,
     sizeof(int)},

    {"net.inet.tcp.sendspace",
     &ngx_freebsd_net_inet_tcp_sendspace,
     sizeof(int)},

     /* FreeBSD 5.0 */

    {"kern.ipc.zero_copy.send",
     &ngx_freebsd_kern_ipc_zero_copy_send,
     sizeof(int)},

    {NULL, NULL, 0}
};


int ngx_os_init(ngx_log_t *log)
{
    int        i, version;
    size_t     size;
    ngx_err_t  err;

    size = sizeof(ngx_freebsd_kern_ostype);
    if (sysctlbyname("kern.ostype",
                     ngx_freebsd_kern_ostype, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.ostype) failed");
        return NGX_ERROR;
    }

    size = sizeof(ngx_freebsd_kern_osrelease);
    if (sysctlbyname("kern.osrelease",
                     ngx_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.osrelease) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %s %s",
                  ngx_freebsd_kern_ostype, ngx_freebsd_kern_osrelease);


    size = sizeof(int);
    if (sysctlbyname("kern.osreldate",
                     &ngx_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.osreldate) failed");
        return NGX_ERROR;
    }

    version = ngx_freebsd_kern_osreldate;

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "kern.osreldate: %d, built on %d",
                  version, __FreeBSD_version);


#if (HAVE_SENDFILE)

    /*
     * The determination of the sendfile() nbytes bug is complex enough.
     * There are two sendfile() syscalls: a new 393 has no bug while
     * an old 336 has the bug in some versions and has not in others.
     * Besides libc_r wrapper also emulates the bug in some versions.
     * There's no way to say exactly if a given FreeBSD version has the bug.
     * Here is the algorithm that works at least for RELEASEs
     * and for syscalls only (not libc_r wrapper).
     *
     * We detect the new sendfile() version available at the compile time
     * to allow an old binary to run correctly on an updated FreeBSD system.
     */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 460102) \
    || __FreeBSD_version == 460002 || __FreeBSD_version >= 500039

    /* a new syscall without the bug */

    ngx_freebsd_sendfile_nbytes_bug = 0;

#else

    /* an old syscall that can have the bug */

    ngx_freebsd_sendfile_nbytes_bug = 1;

#endif

#endif /* HAVE_SENDFILE */


    if ((version < 500000 && version >= 440003) || version >= 500017) {
        ngx_freebsd_use_tcp_nopush = 1;
    }


    for (i = 0; sysctls[i].name; i++) {
        *sysctls[i].value = 0;
        size = sysctls[i].size;
        if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
                                                                       == -1) {
            err = errno;
            if (err != NGX_ENOENT) {
                ngx_log_error(NGX_LOG_ALERT, log, err,
                              "sysctlbyname(%s) failed", sysctls[i].name);
                return NGX_ERROR;
            }

        } else {
            ngx_log_error(NGX_LOG_INFO, log, 0, "%s: %d",
                          sysctls[i].name, *sysctls[i].value);
        }
    }

    return ngx_posix_init(log);
}
