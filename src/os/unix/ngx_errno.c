
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_STRERROR_R)

u_char *
ngx_strerror_r(int err, u_char *errstr, size_t size)
{
    if (size == 0) {
        return errstr;
    }

    errstr[0] = '\0';

    strerror_r(err, (char *) errstr, size);

    while (*errstr && size) {
        errstr++;
        size--;
    }

    return errstr;
}

#elif (NGX_HAVE_GNU_STRERROR_R)

/* Linux strerror_r() */

u_char *
ngx_strerror_r(int err, u_char *errstr, size_t size)
{
    char  *str;

    if (size == 0) {
        return errstr;
    }

    errstr[0] = '\0';

    str = strerror_r(err, (char *) errstr, size);

    if (str != (char *) errstr) {
        return ngx_cpystrn(errstr, (u_char *) str, size);
    }

    while (*errstr && size) {
        errstr++;
        size--;
    }

    return errstr;
}

#endif
