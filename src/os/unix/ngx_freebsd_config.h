
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_FREEBSD_CONFIG_H_INCLUDED_
#define _NGX_FREEBSD_CONFIG_H_INCLUDED_


#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>             /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>

#include <sys/uio.h>
#include <sys/filio.h>          /* FIONBIO */
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sched.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libutil.h>            /* setproctitle() before 4.1 */
#include <osreldate.h>
#include <sys/sysctl.h>
#include <netinet/tcp.h>        /* TCP_NOPUSH */


#if __FreeBSD_version < 400017

#include <sys/param.h>          /* ALIGN() */

/* FreeBSD 3.x has no CMSG_SPACE() at all and has the broken CMSG_DATA() */

#undef  CMSG_SPACE
#define CMSG_SPACE(l)       (ALIGN(sizeof(struct cmsghdr)) + ALIGN(l))

#undef  CMSG_DATA
#define CMSG_DATA(cmsg)     ((u_char *)(cmsg) + ALIGN(sizeof(struct cmsghdr)))

#endif


#include <ngx_auto_config.h>


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


#if (HAVE_KQUEUE)
#include <sys/event.h>
#endif


#if (__FreeBSD_version < 430000 || __FreeBSD_version < 500012)

pid_t rfork_thread(int flags, void *stack, int (*func)(void *arg), void *arg);

#endif

#ifndef IOV_MAX
#define IOV_MAX   1024
#endif


#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif


#define ngx_setproctitle  setproctitle


extern char *malloc_options;


#endif /* _NGX_FREEBSD_CONFIG_H_INCLUDED_ */
