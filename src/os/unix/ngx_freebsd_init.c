
#include <ngx_freebsd_init.h>


int freebsd_kern_osreldate;
int freebsd_hw_ncpu;

int freebsd_sendfile_nbytes_bug;


int ngx_os_init(ngx_log_t *log)
{
    size_t  size;

    size = 4;
    if (sysctlbyname("kern.osreldate",
                     &freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.osreldate) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "kern.osreldate: %d, built on %d",
                  freebsd_kern_osreldate, __FreeBSD_version);


#if HAVE_FREEBSD_SENDFILE

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
    freebsd_sendfile_nbytes_bug = 0;

#else

    /* an old syscall that can have the bug */
    freebsd_sendfile_nbytes_bug = 1;

#endif

#endif /* HAVE_FREEBSD_SENDFILE */


    size = 4;
    if (sysctlbyname("hw.ncpu", &freebsd_hw_ncpu, &size, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(hw.ncpu) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "hw.ncpu: %d", freebsd_hw_ncpu);

    return NGX_OK;
}
