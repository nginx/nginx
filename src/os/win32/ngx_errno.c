
/*
   TODO:
     add WSA error messages for NT and 98
     test for English only messages
*/

#include <ngx_config.h>
#include <ngx_core.h>


ngx_str_t wsa_errors[] = {
    ngx_string("Invalid argument"),                          /* 10022 */
    ngx_null_string,                                         /* 10023 */
    ngx_null_string,                                         /* 10024 */
    ngx_null_string,                                         /* 10025 */
    ngx_null_string,                                         /* 10026 */
    ngx_null_string,                                         /* 10027 */
    ngx_null_string,                                         /* 10028 */
    ngx_null_string,                                         /* 10029 */
    ngx_null_string,                                         /* 10030 */
    ngx_null_string,                                         /* 10031 */
    ngx_null_string,                                         /* 10032 */
    ngx_null_string,                                         /* 10033 */
    ngx_null_string,                                         /* 10034 */
    ngx_string("Resource temporarily unavailable")           /* 10035 */
};


int ngx_strerror_r(ngx_err_t err, char *errstr, size_t size)
{
    int        n;
    u_int      len;
    ngx_err_t  format_error;

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
                        |FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, err,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        errstr, size, NULL);

    if (len == 0) {
        format_error = GetLastError();

        if (format_error == ERROR_MR_MID_NOT_FOUND) {
            n = err - WSABASEERR - 22;

            if (n >= 0 && n < 14) {
                len = wsa_errors[n].len;

                if (len) {
                    if (len > size) {
                        len = size;
                    }

                    ngx_memcpy(errstr, wsa_errors[n].data, len);
                    return len;
                }
            }
        }

        len = ngx_snprintf(errstr, size,
                           "FormatMessage() error:(%d)", format_error);
        return len;

    }

    /* remove ".\r\n\0" */
    while (errstr[len] == '\0' || errstr[len] == CR
           || errstr[len] == LF || errstr[len] == '.')
        --len;

    return ++len;
}
