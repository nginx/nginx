#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


#define WIN32       1

#define STRICT
#define WIN32_LEAN_AND_MEAN

/*
 * we need to include windows.h explicity before winsock2.h because
 * warning 4201 is enabled in windows.h
 */
#include <windows.h>

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

#include <winsock2.h>
#include <mswsock.h>
#include <stddef.h>    /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _MSC_VER
#pragma warning(default:4201)

/* unreferenced formal parameter */
#pragma warning(disable:4100)

/* STUB */
#pragma warning(disable:4127)
#endif

#include <ngx_auto_config.h>


#define ngx_inline   __inline


#ifdef _MSC_VER
typedef unsigned __int32  uint32_t;
#else /* __WATCOMC__ */
typedef unsigned int      uint32_t;
#endif

typedef __int64           int64_t;
typedef unsigned __int64  uint64_t;
typedef u_int             uintptr_t;

typedef int               ssize_t;
typedef long              time_t;
typedef __int64           off_t;
typedef uint32_t          in_addr_t;
typedef int               sig_atomic_t;


#define OFF_T_FMT         "%I64d"
#define SIZE_T_FMT        "%d"
#define SIZE_T_X_FMT      "%x"
#define PID_T_FMT         "%d"
#define TIME_T_FMT        "%lu"
#define PTR_FMT           "%08X"


#define NGX_WIN_NT        200000


#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif

#ifndef HAVE_WIN32_TRANSMITPACKETS
#define HAVE_WIN32_TRANSMITPACKETS  1
#define HAVE_WIN32_TRANSMITFILE     0
#endif

#ifndef HAVE_WIN32_TRANSMITFILE
#define HAVE_WIN32_TRANSMITFILE  1
#endif

#if (HAVE_WIN32_TRANSMITPACKETS) || (HAVE_WIN32_TRANSMITFILE)
#define HAVE_SENDFILE  1
#endif


/* STUB */
#define HAVE_LITTLE_ENDIAN  1


#endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
