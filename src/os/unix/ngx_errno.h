#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <errno.h>
#include <string.h>


typedef int               ngx_err_t;

#define NGX_ENOENT        ENOENT
#define NGX_EINTR         EINTR
#define NGX_EACCES        EACCES
#define NGX_EEXIST        EEXIST
#define NGX_ENOTDIR       ENOTDIR
#define NGX_EAGAIN        EWOULDBLOCK
#define NGX_EINPROGRESS   EINPROGRESS
#define NGX_EADDRINUSE    EADDRINUSE
#define NGX_ECONNRESET    ECONNRESET
#define NGX_ETIMEDOUT     ETIMEDOUT
#define NGX_ECANCELED     ECANCELED
#define NGX_ECHILD        ECHILD
#define NGX_ENOMOREFILES  0



#define ngx_errno                  errno
#define ngx_socket_errno           errno
#define ngx_set_errno(err)         errno = err
#define ngx_set_socket_errno(err)  errno = err

#if 0
#define ngx_strerror(err)          strerror(err)
#endif

#define ngx_strerror_r(err, errstr, size)  \
             ngx_cpystrn(errstr, strerror(err), size) - (errstr)


#endif /* _NGX_ERRNO_H_INCLUDED_ */
