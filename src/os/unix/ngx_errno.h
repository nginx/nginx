
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef int               ngx_err_t;

#define NGX_ENOENT        ENOENT
#define NGX_ESRCH         ESRCH
#define NGX_EINTR         EINTR
#define NGX_ECHILD        ECHILD
#define NGX_ENOMEM        ENOMEM
#define NGX_EACCES        EACCES
#define NGX_EBUSY         EBUSY
#define NGX_EEXIST        EEXIST
#define NGX_ENOTDIR       ENOTDIR
#define NGX_EINVAL        EINVAL
#define NGX_EPIPE         EPIPE
#define NGX_EAGAIN        EWOULDBLOCK
#define NGX_EINPROGRESS   EINPROGRESS
#define NGX_EADDRINUSE    EADDRINUSE
#define NGX_ECONNABORTED  ECONNABORTED
#define NGX_ECONNRESET    ECONNRESET
#define NGX_ENOTCONN      ENOTCONN
#define NGX_ETIMEDOUT     ETIMEDOUT
#define NGX_ECONNREFUSED  ECONNREFUSED
#define NGX_EHOSTUNREACH  EHOSTUNREACH
#define NGX_ECANCELED     ECANCELED
#define NGX_ENOMOREFILES  0



#define ngx_errno                  errno
#define ngx_socket_errno           errno
#define ngx_set_errno(err)         errno = err
#define ngx_set_socket_errno(err)  errno = err


#if (HAVE_STRERROR_R || HAVE_GNU_STRERROR_R)

ngx_int_t ngx_strerror_r(int err, char *errstr, size_t size);

#else

#define ngx_strerror_r(err, errstr, size)  \
             (char *) ngx_cpystrn(errstr, strerror(err), size) - (errstr)

#endif


#endif /* _NGX_ERRNO_H_INCLUDED_ */
