#ifndef _NGX_SENDV_H_INCLUDED_
#define _NGX_SENDV_H_INCLUDED_


#include <ngx_config.h>

typedef WSABUF        ngx_iovec_t;
#define ngx_iov_base  buf
#define ngx_iov_len   len

#define ngx_sendv(s, iovec, n, sent)  WSASend(s, iovec, n, sent, 0, NULL, NULL)


#endif /* _NGX_SENDV_H_INCLUDED_ */
