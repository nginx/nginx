
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char *
ngx_strerror_r(ngx_err_t err, u_char *errstr, size_t size)
{
    u_int  len;

    if (size == 0) {
        return errstr;
    }

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
                        |FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, err,
                        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                        (char *) errstr, size, NULL);

    if (len == 0) {
        return ngx_snprintf(errstr, size,
                            "FormatMessage() error:(%d)", GetLastError());
    }

    /* remove ".\r\n\0" */
    while (errstr[len] == '\0' || errstr[len] == CR
           || errstr[len] == LF || errstr[len] == '.')
    {
        --len;
    }

    return &errstr[++len];
}
