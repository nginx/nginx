#ifndef _NGX_SENDV_H_INCLUDED_
#define _NGX_SENDV_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_connection.h>

typedef WSABUF        ngx_iovec_t;
#define ngx_iov_base  buf
#define ngx_iov_len   len

ssize_t ngx_sendv(ngx_connection_t *c, ngx_iovec_t *iovec, int n);


#endif /* _NGX_SENDV_H_INCLUDED_ */
