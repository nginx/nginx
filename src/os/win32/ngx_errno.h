#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>

typedef DWORD             ngx_err_t;

#define ngx_errno                  GetLastError()
#define ngx_socket_errno           WSAGetLastError()
#define ngx_set_socket_errno(err)  WSASetLastError(err)

#define NGX_ENOENT        ERROR_FILE_NOT_FOUND
#define NGX_EACCES        ERROR_ACCESS_DENIED
#define NGX_EAGAIN        WSAEWOULDBLOCK
#define NGX_EINPROGRESS   WSAEINPROGRESS
#define NGX_EADDRINUSE    WSAEADDRINUSE
#define NGX_ETIMEDOUT     WSAETIMEDOUT

int ngx_strerror_r(ngx_err_t err, char *errstr, size_t size);


#endif /* _NGX_ERRNO_H_INCLUDED_ */
