
/*
   TODO:
     add WSA error messages for NT and 98
     test for English only messages
*/

#include <ngx_config.h>
#include <ngx_core.h>


int ngx_strerror_r(ngx_err_t err, char *errstr, size_t size)
{
    int len;

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
                        | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, err,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        errstr, size, NULL);

    /* add WSA error messages */

    if (len == 0) {

        len = ngx_snprintf(errstr, size,
                           "FormatMessage error:(%d)", GetLastError());
        return len;

    }

    /* remove ".\r\n\0" */
    while (errstr[len] == '\0' || errstr[len] == CR
           || errstr[len] == LF || errstr[len] == '.')
        --len;

    return ++len;
}
