#ifndef _NGX_FREEBSD_CONFIG_H_INCLUDED_
#define _NGX_FREEBSD_CONFIG_H_INCLUDED_


#include <unistd.h>
#include <stddef.h>             /* offsetof */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <osreldate.h>


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


#endif /* _NGX_FREEBSD_CONFIG_H_INCLUDED_ */
