
#include <ngx_config.h>
#include <ngx_core.h>


char ngx_linux_kern_ostype[50];
char ngx_linux_kern_osrelease[20];


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    NULL,
#if (HAVE_SENDFILE)
    ngx_linux_sendfile_chain,
    NGX_IO_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


int ngx_os_init(ngx_log_t *log)
{
    int  name[2], len;

    name[0] = CTL_KERN;
    name[1] = KERN_OSTYPE;
    len = sizeof(ngx_linux_kern_ostype);
    if (sysctl(name, sizeof(name), ngx_linux_kern_ostype, &len, NULL, 0)
                                                                       == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "sysctl(KERN_OSTYPE) failed");
        return NGX_ERROR;
    }

    name[0] = CTL_KERN;
    name[1] = KERN_OSRELEASE;
    len = sizeof(ngx_linux_kern_osrelease);
    if (sysctl(name, sizeof(name), ngx_linux_kern_osrelease, &len, NULL, 0)
                                                                       == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctl(KERN_OSRELEASE) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %s %s",
                  ngx_linux_kern_ostype, ngx_linux_kern_osrelease);


    return ngx_posix_init(log);
}
