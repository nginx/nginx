#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_strerror_r(int err, char *errstr, size_t size)
{
    size_t  len;

    if (size == 0) {
        return 0;
    }

    errstr[0] = '\0';

    strerror_r(err, errstr, size);

    for (len = 0; len < size; len++) {
        if (errstr[len] == '\0') {
            break;
        }
    }

    return len;
}
