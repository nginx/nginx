#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>

typedef DWORD             ngx_err_t;

#define ngx_errno         GetLastError()
#define ngx_socket_errno  WSAGetLastError()

#define NGX_ENOENT        ERROR_FILE_NOT_FOUND
#define NGX_EAGAIN        WSAEWOULDBLOCK

int ngx_strerror_r(ngx_err_t err, char *errstr, size_t size);


#endif /* _NGX_ERRNO_H_INCLUDED_ */
