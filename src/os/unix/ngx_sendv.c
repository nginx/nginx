
#include <ngx_types.h>
#include <ngx_socket.h>
#include <ngx_sendv.h>

ssize_t ngx_sendv(ngx_socket_t s, ngx_iovec_t *iovec, int n, size_t *sent)
{
     ssize_t rc = writev(s, iovec, n);

     if (rc == -1)
         return -1;

     *sent = rc;
     return 0;
}
