#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_


#include <ngx_auto_config.h>

/*
   auto_conf
   ngx_inline inline __inline __inline__
*/

#define FD_SETSIZE  1024


#ifdef _WIN32

#define WIN32 1

#include <winsock2.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdarg.h>


#define ngx_inline   __inline

#define ngx_memzero  ZeroMemory

#define ngx_close_socket closesocket

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

#else /* POSIX */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ngx_inline   inline

#define ngx_memzero  bzero

#define ngx_close_socket close

#endif /* POSIX */



#define LF     10
#define CR     13
#define CRLF   "\x0d\x0a"



#if defined SO_ACCEPTFILTER || defined TCP_DEFER_ACCEPT

#ifndef HAVE_DEFERRED_ACCEPT
#define HAVE_DEFERRED_ACCEPT  1
#endif

#endif



#ifdef __FreeBSD__

#include <osreldate.h>

#if __FreeBSD_version >= 300007

#ifndef HAVE_FREEBSD_SENDFILE
#define HAVE_FREEBSD_SENDFILE  1
#endif

#ifndef HAVE_FREEBSD_SENDFILE_NBYTES_BUG
#define HAVE_FREEBSD_SENDFILE_NBYTES_BUG  2
#endif

#endif

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 460100) \
    || __FreeBSD_version == 460001
    || __FreeBSD_version >= 500029

#if (HAVE_FREEBSD_SENDFILE_NBYTES_BUG == 2)
#define HAVE_FREEBSD_SENDFILE_NBYTES_BUG  0
#endif

#endif

#if (HAVE_FREEBSD_SENDFILE)
#define HAVE_SENDFILE  1
#endif


#if (__FreeBSD__ == 4 && __FreeBSD_version >= 410000) \
    || __FreeBSD_version >= 500011

#ifndef HAVE_KQUEUE
#define HAVE_KQUEUE  1
#include <sys/event.h>
#endif

#endif


#endif /* __FreeBSD__ */


#endif /* _NGX_CONFIG_H_INCLUDED_ */
