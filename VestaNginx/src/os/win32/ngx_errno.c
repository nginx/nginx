
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char *
ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
{
    u_int          len;
    static u_long  lang = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);

    if (size == 0) {
        return errstr;
    }

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                        NULL, err, lang, (char *) errstr, size, NULL);

    if (len == 0 && lang) {

        /*
         * Try to use English messages first and fallback to a language,
         * based on locale: non-English Windows have no English messages
         * at all.  This way allows to use English messages at least on
         * Windows with MUI.
         */

        lang = 0;

        len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                            NULL, err, lang, (char *) errstr, size, NULL);
    }

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


ngx_int_t
ngx_strerror_init(void)
{
    return NGX_OK;
}
