#ifndef _NGX_FREEBSD_CONFIG_H_INCLUDED_
#define _NGX_FREEBSD_CONFIG_H_INCLUDED_


#include <unistd.h>
#include <stddef.h>             /* offsetof */
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        /* TCP_NOPUSH */
#include <arpa/inet.h>
#include <netdb.h>
#include <osreldate.h>


/* TODO: autoconf */
#if __FreeBSD_version < 300007
typedef u_int64_t  uint64_t;
typedef u_int32_t  uintptr_t;
#endif


#if __FreeBSD_version < 330002  /* exactly */
typedef uint32_t   socklen_t;
#endif


#if (i386)

#define OFF_FMT    "%lld"
#define SIZE_FMT   "%d"
#define SIZEX_FMT  "%x"

#else  /* amd64, alpha, sparc64, ia64 */

#define OFF_FMT    "%ld"
#define SIZE_FMT   "%ld"
#define SIZEX_FMT  "%lx"

#endif

#define TIME_FMT   "%lu"
#define PID_FMT    "%d"
#define RLIM_FMT   "%lld"


#ifndef HAVE_SELECT
#define HAVE_SELECT  1
#endif


#ifndef HAVE_POLL
#define HAVE_POLL  1
#endif
#if (HAVE_POLL)
#include <poll.h>
#endif

       /* FreeBSD aio supported via kqueue */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500014

#ifndef HAVE_AIO
#define HAVE_AIO  1
#endif

#endif

#if (HAVE_AIO)
#include <aio.h>
#endif


#if defined SO_ACCEPTFILTER && !defined HAVE_DEFERRED_ACCEPT
#define HAVE_DEFERRED_ACCEPT  1
#endif


/* STUB */
#define HAVE_PREAD         1
#define HAVE_PWRITE        1
#define HAVE_LOCALTIME_R   1


       /* FreeBSD sendfile */

#if __FreeBSD_version >= 300007

#ifndef HAVE_FREEBSD_SENDFILE
#define HAVE_FREEBSD_SENDFILE    1
#endif

#endif


#if (HAVE_FREEBSD_SENDFILE)
#define HAVE_SENDFILE  1
#endif


       /* FreeBSD kqueue */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 410000) \
    || __FreeBSD_version >= 500011

#ifndef HAVE_KQUEUE
#define HAVE_KQUEUE  1
#endif

#endif

#if (HAVE_KQUEUE)
#include <sys/event.h>
#endif


       /* kqueue's NOTE_LOWAT */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500018

#ifndef HAVE_LOWAT_EVENT
#define HAVE_LOWAT_EVENT  1
#endif

#endif




#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif


#ifndef HAVE_FIONBIO
#define HAVE_FIONBIO   1
#endif


/* STUB */
#define HAVE_LITTLE_ENDIAN  1


#endif /* _NGX_FREEBSD_CONFIG_H_INCLUDED_ */
