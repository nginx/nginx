#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


#define WIN32 1


#include <winsock2.h>
#include <mswsock.h>
#include <stddef.h>    /* offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <time.h>      /* gmtime, strftime */


#define ngx_inline   __inline


#if 0
typedef unsigned __int32  uint32_t;
#else
typedef unsigned int      uint32_t;
#endif
typedef __int64           int64_t;
typedef unsigned __int64  uint64_t;
typedef u_int             uintptr_t;

typedef int               ssize_t;
typedef long              time_t;
typedef unsigned __int64  off_t;


#define OFF_FMT    "%I64d"
#define SIZE_FMT   "%d"
#define SIZEX_FMT  "%x"
#define PID_FMT    "%d"


/* STUB */
typedef uint32_t     u_int32_t;


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
