
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef int               ngx_err_t;

#define NGX_EPERM         EPERM
#define NGX_ENOENT        ENOENT
#define NGX_ENOPATH       ENOENT
#define NGX_ESRCH         ESRCH
#define NGX_EINTR         EINTR
#define NGX_ECHILD        ECHILD
#define NGX_ENOMEM        ENOMEM
#define NGX_EACCES        EACCES
#define NGX_EBUSY         EBUSY
#define NGX_EEXIST        EEXIST
#define NGX_EXDEV         EXDEV
#define NGX_ENOTDIR       ENOTDIR
#define NGX_EISDIR        EISDIR
#define NGX_EINVAL        EINVAL
#define NGX_ENOSPC        ENOSPC
#define NGX_EPIPE         EPIPE
#define NGX_EINPROGRESS   EINPROGRESS
#define NGX_EADDRINUSE    EADDRINUSE
#define NGX_ECONNABORTED  ECONNABORTED
#define NGX_ECONNRESET    ECONNRESET
#define NGX_ENOTCONN      ENOTCONN
#define NGX_ETIMEDOUT     ETIMEDOUT
#define NGX_ECONNREFUSED  ECONNREFUSED
#define NGX_ENAMETOOLONG  ENAMETOOLONG
#define NGX_ENETDOWN      ENETDOWN
#define NGX_ENETUNREACH   ENETUNREACH
#define NGX_EHOSTDOWN     EHOSTDOWN
#define NGX_EHOSTUNREACH  EHOSTUNREACH
#define NGX_ENOSYS        ENOSYS
#define NGX_ECANCELED     ECANCELED
#define NGX_EILSEQ        EILSEQ
#define NGX_ENOMOREFILES  0

#if (__hpux__)
#define NGX_EAGAIN        EWOULDBLOCK
#else
#define NGX_EAGAIN        EAGAIN
#endif


#define ngx_errno                  errno
#define ngx_socket_errno           errno
#define ngx_set_errno(err)         errno = err
#define ngx_set_socket_errno(err)  errno = err


#if (NGX_HAVE_STRERROR_R || NGX_HAVE_GNU_STRERROR_R)

u_char *ngx_strerror_r(int err, u_char *errstr, size_t size);

#else

/* Solaris and Tru64 UNIX have thread-safe strerror() */

#define ngx_strerror_r(err, errstr, size)                                    \
    ngx_cpystrn(errstr, (u_char *) strerror(err), size)

#endif


#if (NGX_HAVE_SYS_ERRLIST)

#define ngx_sigsafe_strerror(err)                                            \
    (err > 0 && err < sys_nerr) ? sys_errlist[err] : "Unknown error"

#else

#define ngx_sigsafe_strerror(err)  ""

#endif


#endif /* _NGX_ERRNO_H_INCLUDED_ */
