
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_connection.h>
#include <ngx_log.h>
#include <ngx_sendv.h>

#include <ngx_string.h>

ssize_t ngx_sendv(ngx_connection_t *c, ngx_iovec_t *iovec, int n)
{
    int         rc;
    size_t      sent;
    ngx_err_t   err;

#if 0
    /* STUB: WSABUF must be 4-byte aligned. Undocumented WSAEINVAL error */
    ngx_iovec_t iov[10];
    ngx_memcpy(iov, iovec, n * sizeof(ngx_iovec_t));
#endif

    sent = 0;

    ngx_log_debug(c->log, "WSASend: %d, %d, %08x" _ c->fd _ n _ iovec);

    rc = WSASend(c->fd, iovec, n, &sent, 0, NULL, NULL);

    ngx_log_debug(c->log, "WSASend() done");

    if (rc == SOCKET_ERROR) {
        err = ngx_socket_errno;

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "WSASend() eagain");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "WSASend() failed");
        return NGX_ERROR;
    }

    return sent;
}
