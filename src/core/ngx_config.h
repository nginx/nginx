#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_


#include <ngx_auto_config.h>

/*
   auto_conf
   ngx_inline inline __inline __inline__
*/

/* STUB */
#undef  FD_SETSIZE
#define FD_SETSIZE  1024


/* auto_conf */
#define NGX_ALIGN       (4 - 1)
#define NGX_ALIGN_TYPE  unsigned

#define ngx_align(p)    (char *) (((NGX_ALIGN_TYPE) p + NGX_ALIGN) & ~NGX_ALIGN)



/* Platform specific: array[NGX_INVALID_ARRAY_INDEX] should cause SIGSEGV */
#define NGX_INVALID_ARRAY_INDEX 0x80000000


#ifdef _WIN32

#define WIN32 1

#include <winsock2.h>
#include <mswsock.h>
#include <stddef.h>    /* offsetof */
#include <stdio.h>
#include <stdarg.h>


#define ngx_inline   __inline


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

#else /* POSIX */



/* Solaris */
#if defined(sun) && (defined(__svr4__) || defined(__SVR4))

#define SOLARIS  1

#define _FILE_OFFSET_BITS  64  /* should be before sys/types.h */

#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif

#include <sys/stropts.h>        /* INFTIM */

#endif /* Solaris */



#include <unistd.h>
#include <stddef.h>             /* offsetof */
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
#include <netdb.h>


#ifndef HAVE_POLL
#define HAVE_POLL  1
#include <poll.h>
#endif


#if (HAVE_DEVPOLL)
#include <sys/ioctl.h>
#include <sys/devpoll.h>        /* Solaris, HP/UX */
#endif


#if (HAVE_AIO)
#include <aio.h>
#endif


#define ngx_inline   inline


#endif /* POSIX */



#define LF     10
#define CR     13
#define CRLF   "\x0d\x0a"


#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif


#if defined SO_ACCEPTFILTER || defined TCP_DEFER_ACCEPT

#ifndef HAVE_DEFERRED_ACCEPT
#define HAVE_DEFERRED_ACCEPT  1
#endif

#endif


#ifndef HAVE_SELECT
#define HAVE_SELECT 1
#endif


#ifdef __FreeBSD__

#include <osreldate.h>

#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif

/* FreeBSD sendfile */
#if __FreeBSD_version >= 300007

#ifndef HAVE_FREEBSD_SENDFILE
#define HAVE_FREEBSD_SENDFILE  1
#endif

#ifndef HAVE_FREEBSD_SENDFILE_NBYTES_BUG
#define HAVE_FREEBSD_SENDFILE_NBYTES_BUG  2
#endif

#endif /* FreeBSD sendfile */

/* FreeBSD sendfile nbytes bug */
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 460100) \
    || __FreeBSD_version == 460001
    || __FreeBSD_version >= 500029

#if (HAVE_FREEBSD_SENDFILE_NBYTES_BUG == 2)
#define HAVE_FREEBSD_SENDFILE_NBYTES_BUG  0
#endif

#endif /* FreeBSD sendfile nbytes bug */

#if (HAVE_FREEBSD_SENDFILE)
#define HAVE_SENDFILE  1
#endif


/* FreeBSD kqueue */
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 410000) \
    || __FreeBSD_version >= 500011

#ifndef HAVE_KQUEUE
#define HAVE_KQUEUE  1
#include <sys/event.h>
#endif

/* kqueue's NOTE_LOWAT */
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500018

#ifndef HAVE_LOWAT_EVENT
#define HAVE_LOWAT_EVENT  1
#endif

#endif

#endif /* FreeBSD kqueue */


#endif /* __FreeBSD__ */


#ifdef __SOME_OS_TEMPLATE__

#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif

#endif


#endif /* _NGX_CONFIG_H_INCLUDED_ */
