
/*
 * Copyright (C) Igor Sysoev
 */


/*
 * TODO:
 *   add WSA error messages for NT and 98
 *   test for English only messages
 */

#include <ngx_config.h>
#include <ngx_core.h>


static ngx_str_t  wsa_errors[] = {
    ngx_string("An invalid argument was supplied"),      /* WSAEINVAL 10022 */
    ngx_string("Too many open sockets"),                 /* WSAEMFILE 10023 */

    ngx_null_string,                                               /* 10024 */
    ngx_null_string,                                               /* 10025 */
    ngx_null_string,                                               /* 10026 */
    ngx_null_string,                                               /* 10027 */
    ngx_null_string,                                               /* 10028 */
    ngx_null_string,                                               /* 10029 */
    ngx_null_string,                                               /* 10030 */
    ngx_null_string,                                               /* 10031 */
    ngx_null_string,                                               /* 10032 */
    ngx_null_string,                                               /* 10033 */
    ngx_null_string,                                               /* 10034 */

    /* WSAEWOULDBLOCK 10035 */
    ngx_string("A non-blocking socket operation could not be completed "
               "immediately"),

    ngx_null_string,                                               /* 10036 */
    ngx_null_string,                                               /* 10037 */

    /* WSAENOTSOCK 10038 */
    ngx_string("An operation was attempted on something that is not a socket"),

    ngx_null_string,                                               /* 10039 */
    ngx_null_string,                                               /* 10040 */
    ngx_null_string,                                               /* 10041 */

    /* WSAENOPROTOOPT 10042 */
    ngx_string("An unknown, invalid, or unsupported option or level was "
               "specified in a getsockopt or setsockopt call"),

    ngx_null_string,                                               /* 10043 */
    ngx_null_string,                                               /* 10044 */
    ngx_null_string,                                               /* 10045 */
    ngx_null_string,                                               /* 10046 */
    ngx_null_string,                                               /* 10047 */
    ngx_null_string,                                               /* 10048 */
    ngx_null_string,                                               /* 10049 */
    ngx_null_string,                                               /* 10050 */
    ngx_null_string,                                               /* 10051 */
    ngx_null_string,                                               /* 10052 */
    ngx_null_string,                                               /* 10053 */

    /* WSAECONNRESET 10054 */
    ngx_string("An existing connection was forcibly closed by the remote host"),

    /* WSAENOBUFS 10055 */
    ngx_string("An operation on a socket could not be performed because "
               "the system lacked sufficient buffer space or "
               "because a queue was full"),

    /* WSAEISCONN 10056 */
    ngx_string("A connect request was made on an already connected socket"),

    /* WSAENOTCONN 10057 */
    ngx_string("A request to send or receive data was disallowed because"
               "the socket is not connected and (when sending on a datagram "
               "socket using a sendto call) no address was supplied"),

    ngx_null_string,                                               /* 10058 */
    ngx_null_string,                                               /* 10059 */

    /* WSAETIMEDOUT 10060 */
    ngx_string("A connection attempt failed because the connected party "
               "did not properly respond after a period of time, "
               "or established connection failed because connected host "
               "has failed to respond"),

    /* WSAECONNREFUSED 10061 */
    ngx_string("No connection could be made because the target machine "
               "actively refused it")
};


u_char *ngx_strerror_r(ngx_err_t err, u_char *errstr, size_t size)
{
    int        n;
    u_int      len;
    ngx_err_t  format_error;

    if (size == 0) {
        return errstr;
    }

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
                        |FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, err,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (char *) errstr, size, NULL);

    if (len == 0) {
        format_error = GetLastError();

        if (format_error == ERROR_MR_MID_NOT_FOUND) {
            n = err - WSAEINVAL;

            if (n >= 0 && n <= WSAECONNREFUSED - WSAEINVAL) {
                len = wsa_errors[n].len;

                if (len) {
                    if (len > size) {
                        len = size;
                    }

                    ngx_memcpy(errstr, wsa_errors[n].data, len);

                    return errstr + len;
                }
            }
        }

        return ngx_snprintf(errstr, size,
                            "FormatMessage() error:(%d)", format_error);
    }

    /* remove ".\r\n\0" */
    while (errstr[len] == '\0' || errstr[len] == CR
           || errstr[len] == LF || errstr[len] == '.')
    {
        --len;
    }

    return &errstr[++len];
}
