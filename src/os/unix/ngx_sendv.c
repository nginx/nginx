
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_connection.h>
#include <ngx_log.h>
#include <ngx_sendv.h>

ssize_t ngx_sendv(ngx_connection_t *c, ngx_iovec_t *iovec, int n)
{
    ssize_t rc;
    ngx_err_t err;

    rc = writev(c->fd, iovec, n);

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "sendv() eagain");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "sendv() failed");
        return NGX_ERROR;
    }

    return rc;
}
