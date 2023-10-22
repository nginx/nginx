
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The strerror() messages are copied because:
 *
 * 1) strerror() and strerror_r() functions are not Async-Signal-Safe,
 *    therefore, they cannot be used in signal handlers;
 *
 * 2) a direct sys_errlist[] array may be used instead of these functions,
 *    but Linux linker warns about its usage:
 *
 * warning: `sys_errlist' is deprecated; use `strerror' or `strerror_r' instead
 * warning: `sys_nerr' is deprecated; use `strerror' or `strerror_r' instead
 *
 *    causing false bug reports.
 */


static ngx_str_t  *ngx_sys_errlist;
static ngx_str_t   ngx_unknown_error = ngx_string("Unknown error");


u_char *
ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
{
    ngx_str_t  *msg;

    msg = ((ngx_uint_t) err < NGX_SYS_NERR) ? &ngx_sys_errlist[err]:
                                              &ngx_unknown_error;
    size = ngx_min(size, msg->len);

    return ngx_cpymem(errstr, msg->data, size);
}


ngx_int_t
ngx_strerror_init(void)
{
    char       *msg;
    u_char     *p;
    size_t      len;
    ngx_err_t   err;

    /*
     * ngx_strerror() is not ready to work at this stage, therefore,
     * malloc() is used and possible errors are logged using strerror().
     */

    len = NGX_SYS_NERR * sizeof(ngx_str_t);

    ngx_sys_errlist = malloc(len);
    if (ngx_sys_errlist == NULL) {
        goto failed;
    }

    for (err = 0; err < NGX_SYS_NERR; err++) {
        msg = strerror(err);
        len = ngx_strlen(msg);

        p = malloc(len);
        if (p == NULL) {
            goto failed;
        }

        ngx_memcpy(p, msg, len);
        ngx_sys_errlist[err].len = len;
        ngx_sys_errlist[err].data = p;
    }

    return NGX_OK;

failed:

    err = errno;
    ngx_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));

    return NGX_ERROR;
}
