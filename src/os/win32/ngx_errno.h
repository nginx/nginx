
/*
 * Copyright (C) Igor Sysoev
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

#define NGX_ENOENT                 ERROR_FILE_NOT_FOUND
#define NGX_EACCES                 ERROR_ACCESS_DENIED
#define NGX_EEXIST                 ERROR_FILE_EXISTS
#define NGX_ENOTDIR                ERROR_PATH_NOT_FOUND
#define NGX_EPIPE                  EPIPE
#define NGX_EAGAIN                 WSAEWOULDBLOCK
#define NGX_EINPROGRESS            WSAEINPROGRESS
#define NGX_EADDRINUSE             WSAEADDRINUSE
#define NGX_ECONNABORTED           WSAECONNABORTED
#define NGX_ECONNRESET             WSAECONNRESET
#define NGX_ENOTCONN               WSAENOTCONN
#define NGX_ETIMEDOUT              WSAETIMEDOUT
#define NGX_ECONNREFUSED           WSAECONNREFUSED
#define NGX_EHOSTUNREACH           WSAEHOSTUNREACH
#define NGX_ENOMOREFILES           ERROR_NO_MORE_FILES

#define NGX_EALREADY               WSAEALREADY
#define NGX_EINVAL                 WSAEINVAL

int ngx_strerror_r(ngx_err_t err, char *errstr, size_t size);


#endif /* _NGX_ERRNO_H_INCLUDED_ */
