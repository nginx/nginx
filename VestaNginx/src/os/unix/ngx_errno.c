
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_str_t   ngx_unknown_error = ngx_string("Unknown error");


#if (NGX_HAVE_STRERRORDESC_NP)

/*
 * The strerrordesc_np() function, introduced in glibc 2.32, is
 * async-signal-safe.  This makes it possible to use it directly,
 * without copying error messages.
 */


u_char *
ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
{
    size_t       len;
    const char  *msg;

    msg = strerrordesc_np(err);

    if (msg == NULL) {
        msg = (char *) ngx_unknown_error.data;
        len = ngx_unknown_error.len;

    } else {
        len = ngx_strlen(msg);
    }

    size = ngx_min(size, len);

    return ngx_cpymem(errstr, msg, size);
}


ngx_int_t
ngx_strerror_init(void)
{
    return NGX_OK;
}


#else

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
static ngx_err_t   ngx_first_error;
static ngx_err_t   ngx_last_error;


u_char *
ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
{
    ngx_str_t  *msg;

    if (err >= ngx_first_error && err < ngx_last_error) {
        msg = &ngx_sys_errlist[err - ngx_first_error];

    } else {
        msg = &ngx_unknown_error;
    }

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

#if (NGX_SYS_NERR)
    ngx_first_error = 0;
    ngx_last_error = NGX_SYS_NERR;

#elif (EPERM > 1000 && EPERM < 0x7fffffff - 1000)

    /*
     * If number of errors is not known, and EPERM error code has large
     * but reasonable value, guess possible error codes based on the error
     * messages returned by strerror(), starting from EPERM.  Notably,
     * this covers GNU/Hurd, where errors start at 0x40000001.
     */

    for (err = EPERM; err > EPERM - 1000; err--) {
        ngx_set_errno(0);
        msg = strerror(err);

        if (errno == EINVAL
            || msg == NULL
            || strncmp(msg, "Unknown error", 13) == 0)
        {
            continue;
        }

        ngx_first_error = err;
    }

    for (err = EPERM; err < EPERM + 1000; err++) {
        ngx_set_errno(0);
        msg = strerror(err);

        if (errno == EINVAL
            || msg == NULL
            || strncmp(msg, "Unknown error", 13) == 0)
        {
            continue;
        }

        ngx_last_error = err + 1;
    }

#else

    /*
     * If number of errors is not known, guess it based on the error
     * messages returned by strerror().
     */

    ngx_first_error = 0;

    for (err = 0; err < 1000; err++) {
        ngx_set_errno(0);
        msg = strerror(err);

        if (errno == EINVAL
            || msg == NULL
            || strncmp(msg, "Unknown error", 13) == 0)
        {
            continue;
        }

        ngx_last_error = err + 1;
    }

#endif

    /*
     * ngx_strerror() is not ready to work at this stage, therefore,
     * malloc() is used and possible errors are logged using strerror().
     */

    len = (ngx_last_error - ngx_first_error) * sizeof(ngx_str_t);

    ngx_sys_errlist = malloc(len);
    if (ngx_sys_errlist == NULL) {
        goto failed;
    }

    for (err = ngx_first_error; err < ngx_last_error; err++) {
        msg = strerror(err);

        if (msg == NULL) {
            ngx_sys_errlist[err - ngx_first_error] = ngx_unknown_error;
            continue;
        }

        len = ngx_strlen(msg);

        p = malloc(len);
        if (p == NULL) {
            goto failed;
        }

        ngx_memcpy(p, msg, len);
        ngx_sys_errlist[err - ngx_first_error].len = len;
        ngx_sys_errlist[err - ngx_first_error].data = p;
    }

    return NGX_OK;

failed:

    err = errno;
    ngx_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));

    return NGX_ERROR;
}

#endif
