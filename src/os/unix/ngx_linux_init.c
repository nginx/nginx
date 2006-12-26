
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_int_t ngx_linux_procfs(char *name, char *buf, size_t len,
    ngx_log_t *log);


char  ngx_linux_kern_ostype[50];
char  ngx_linux_kern_osrelease[50];

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
    int        name[2];
    size_t     len;
    ngx_err_t  err;

    if (ngx_linux_procfs("/proc/sys/kernel/ostype",
                         ngx_linux_kern_ostype,
                         sizeof(ngx_linux_kern_ostype), log)
        == -1)
    {
        return NGX_ERROR;
    }

    if (ngx_linux_procfs("/proc/sys/kernel/osrelease",
                         ngx_linux_kern_osrelease,
                         sizeof(ngx_linux_kern_osrelease), log)
        == -1)
    {
        return NGX_ERROR;
    }


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


static ngx_int_t
ngx_linux_procfs(char *name, char *buf, size_t len, ngx_log_t *log)
{
    int       n;
    ngx_fd_t  fd;

    fd = open(name, O_RDONLY);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "open(\"%s\") failed", name);

        return NGX_ERROR;
    }

    n = read(fd, buf, len);

    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "read(\"%s\") failed", name);

    } else {
        if (buf[n - 1] == '\n') {
            buf[--n] = '\0';
        }
    }

    ngx_close_file(fd);

    return n;
}
