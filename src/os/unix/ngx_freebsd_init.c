
#include <ngx_freebsd_init.h>


char ngx_freebsd_kern_ostype[20];
char ngx_freebsd_kern_osrelease[20];
int ngx_freebsd_kern_osreldate;
int ngx_freebsd_hw_ncpu;
int ngx_freebsd_net_inet_tcp_sendspace;
int ngx_freebsd_sendfile_nbytes_bug;


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    NULL,
    ngx_freebsd_sendfile_chain,
    NGX_HAVE_SENDFILE|NGX_HAVE_ZEROCOPY
};


int ngx_os_init(ngx_log_t *log)
{
    size_t  size;

    size = 20;
    if (sysctlbyname("kern.ostype",
                     ngx_freebsd_kern_ostype, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.ostype) failed");
        return NGX_ERROR;
    }

    size = 20;
    if (sysctlbyname("kern.osrelease",
                     ngx_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.osrelease) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %s %s",
                  ngx_freebsd_kern_ostype, ngx_freebsd_kern_osrelease);


    size = 4;
    if (sysctlbyname("kern.osreldate",
                     &ngx_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.osreldate) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "kern.osreldate: %d, built on %d",
                  ngx_freebsd_kern_osreldate, __FreeBSD_version);


#if (HAVE_FREEBSD_SENDFILE)

    /* The determination of the sendfile() nbytes bug is complex enough.
       There're two sendfile() syscalls: a new 393 has no bug while
       an old 336 has the bug in some versions and has not in others.
       libc_r wrapper also emulates the bug in some versions.
       There's no way to say exactly if a given FreeBSD version has bug.
       Here is the algorithm that work at least for RELEASEs
       and for syscalls only (not libc_r wrapper). */

    /* detect was the new sendfile() version available at the compile time
       to allow an old binary to run correctly on an updated FreeBSD system. */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 460102) \
    || __FreeBSD_version == 460002 || __FreeBSD_version >= 500039

    /* a new syscall without the bug */
    ngx_freebsd_sendfile_nbytes_bug = 0;

#else

    /* an old syscall that can have the bug */
    ngx_freebsd_sendfile_nbytes_bug = 1;

#endif

#endif /* HAVE_FREEBSD_SENDFILE */


    size = 4;
    if (sysctlbyname("hw.ncpu", &ngx_freebsd_hw_ncpu, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(hw.ncpu) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "hw.ncpu: %d", ngx_freebsd_hw_ncpu);


    size = 4;
    if (sysctlbyname("net.inet.tcp.sendspace",
                     &ngx_freebsd_net_inet_tcp_sendspace,
                     &size, NULL, 0) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(net.inet.tcp.sendspace) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "net.inet.tcp.sendspace: %d",
                  ngx_freebsd_net_inet_tcp_sendspace);

    return ngx_posix_init(log);
}
