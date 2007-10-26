
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char  ngx_linux_kern_ostype[50];
u_char  ngx_linux_kern_osrelease[50];

int   ngx_linux_rtsig_max;


static ngx_os_io_t ngx_linux_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_unix_send,
#if (NGX_HAVE_SENDFILE)
    ngx_linux_sendfile_chain,
    NGX_IO_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


ngx_int_t
ngx_os_specific_init(ngx_log_t *log)
{
    int             name[2];
    size_t          len;
    ngx_err_t       err;
    struct utsname  u;

    if (uname(&u) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "uname() failed");
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(ngx_linux_kern_ostype, (u_char *) u.sysname,
                       sizeof(ngx_linux_kern_ostype));

    (void) ngx_cpystrn(ngx_linux_kern_osrelease, (u_char *) u.release,
                       sizeof(ngx_linux_kern_osrelease));

    name[0] = CTL_KERN;
    name[1] = KERN_RTSIGMAX;
    len = sizeof(ngx_linux_rtsig_max);

    if (sysctl(name, 2, &ngx_linux_rtsig_max, &len, NULL, 0) == -1) {
        err = ngx_errno;

        if (err != NGX_ENOTDIR && err != NGX_ENOSYS) {
            ngx_log_error(NGX_LOG_ALERT, log, err,
                          "sysctl(KERN_RTSIGMAX) failed");

            return NGX_ERROR;
        }

        ngx_linux_rtsig_max = 0;
    }


    ngx_os_io = ngx_linux_io;

    return NGX_OK;
}


void
ngx_os_specific_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
                  ngx_linux_kern_ostype, ngx_linux_kern_osrelease);

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "sysctl(KERN_RTSIGMAX): %d",
                  ngx_linux_rtsig_max);
}
