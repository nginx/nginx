#ifndef _NGX_SENDV_H_INCLUDED_
#define _NGX_SENDV_H_INCLUDED_


#include <ngx_types.h>

typedef struct iovec  ngx_iovec_t;
#define ngx_iov_base  iov_base
#define ngx_iov_len   iov_len

ssize_t ngx_sendv(ngx_socket_t s, ngx_iovec_t *iovec, int n, size_t *sent);


#endif /* _NGX_SENDV_H_INCLUDED_ */
