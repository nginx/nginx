#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <errno.h>
#include <string.h>

typedef int               ngx_err_t;

#define NGX_ENOENT        ENOENT
#define NGX_EINTR         EINTR
#define NGX_EAGAIN        EWOULDBLOCK
#define NGX_EADDRINUSE    EADDRINUSE

#define ngx_errno                  errno
#define ngx_socket_errno           errno
#define ngx_set_socket_errno(err)  errno = err

#define ngx_strerror_r(err, errstr, size)  \
             ngx_cpystrn(errstr, strerror(err), size) - (errstr)


#endif /* _NGX_ERRNO_H_INCLUDED_ */
