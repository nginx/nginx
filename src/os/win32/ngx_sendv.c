
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_connection.h>
#include <ngx_log.h>
#include <ngx_sendv.h>

ssize_t ngx_sendv(ngx_connection_t *c, ngx_iovec_t *iovec, int n)
{
     int        rc;
     size_t     sent;
     ngx_err_t  err;

     ngx_log_debug(c->log, "WSASend() start");

     rc = WSASend(c->fd, iovec, n, &sent, 0, NULL, NULL);

     ngx_log_debug(c->log, "WSASend() done");

     if (rc == -1) {
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
