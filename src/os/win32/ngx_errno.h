
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef DWORD                      ngx_err_t;

#define ngx_errno                  GetLastError()
#define ngx_set_errno(err)         SetLastError(err)
#define ngx_socket_errno           WSAGetLastError()
#define ngx_set_socket_errno(err)  WSASetLastError(err)

#define NGX_EPERM                  ERROR_ACCESS_DENIED
#define NGX_ENOENT                 ERROR_FILE_NOT_FOUND
#define NGX_ENOPATH                ERROR_PATH_NOT_FOUND
#define NGX_ENOMEM                 ERROR_NOT_ENOUGH_MEMORY
#define NGX_EACCES                 ERROR_ACCESS_DENIED
/*
 * there are two EEXIST error codes:
 * ERROR_FILE_EXISTS used by CreateFile(CREATE_NEW),
 * and ERROR_ALREADY_EXISTS used by CreateDirectory();
 * MoveFile() uses both
 */
#define NGX_EEXIST                 ERROR_ALREADY_EXISTS
#define NGX_EEXIST_FILE            ERROR_FILE_EXISTS
#define NGX_EXDEV                  ERROR_NOT_SAME_DEVICE
#define NGX_ENOTDIR                ERROR_PATH_NOT_FOUND
#define NGX_EISDIR                 ERROR_CANNOT_MAKE
#define NGX_ENOSPC                 ERROR_DISK_FULL
#define NGX_EPIPE                  EPIPE
#define NGX_EAGAIN                 WSAEWOULDBLOCK
#define NGX_EINPROGRESS            WSAEINPROGRESS
#define NGX_ENOPROTOOPT            WSAENOPROTOOPT
#define NGX_EOPNOTSUPP             WSAEOPNOTSUPP
#define NGX_EADDRINUSE             WSAEADDRINUSE
#define NGX_ECONNABORTED           WSAECONNABORTED
#define NGX_ECONNRESET             WSAECONNRESET
#define NGX_ENOTCONN               WSAENOTCONN
#define NGX_ETIMEDOUT              WSAETIMEDOUT
#define NGX_ECONNREFUSED           WSAECONNREFUSED
#define NGX_ENAMETOOLONG           ERROR_BAD_PATHNAME
#define NGX_ENETDOWN               WSAENETDOWN
#define NGX_ENETUNREACH            WSAENETUNREACH
#define NGX_EHOSTDOWN              WSAEHOSTDOWN
#define NGX_EHOSTUNREACH           WSAEHOSTUNREACH
#define NGX_ENOMOREFILES           ERROR_NO_MORE_FILES
#define NGX_EILSEQ                 ERROR_NO_UNICODE_TRANSLATION
#define NGX_ELOOP                  0
#define NGX_EBADF                  WSAEBADF
#define NGX_EMSGSIZE               WSAEMSGSIZE

#define NGX_EALREADY               WSAEALREADY
#define NGX_EINVAL                 WSAEINVAL
#define NGX_EMFILE                 WSAEMFILE
#define NGX_ENFILE                 WSAEMFILE


u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
ngx_int_t ngx_strerror_init(void);


#endif /* _NGX_ERRNO_H_INCLUDED_ */
