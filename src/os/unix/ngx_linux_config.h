
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_LINUX_CONFIG_H_INCLUDED_
#define _NGX_LINUX_CONFIG_H_INCLUDED_


#define _GNU_SOURCE             /* pread(), pwrite(), gethostname() */

#define _FILE_OFFSET_BITS  64
#define _LARGEFILE_SOURCE


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

#include <time.h>               /* tzset() */
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <netinet/tcp.h>        /* TCP_CORK */


#include <ngx_auto_config.h>


#if (HAVE_PRCTL)
#include <sys/prctl.h>
#endif

#if (HAVE_SENDFILE64)
#include <sys/sendfile.h>
#else
extern ssize_t sendfile(int s, int fd, int32_t *offset, size_t size);
#endif



#ifndef HAVE_SELECT
#define HAVE_SELECT  1
#endif


#ifndef HAVE_POLL
#define HAVE_POLL  1
#endif
#if (HAVE_POLL)
#include <poll.h>
#endif

#if (HAVE_EPOLL)
#include <sys/epoll.h>
#endif /* HAVE_EPOLL */


#if defined TCP_DEFER_ACCEPT && !defined HAVE_DEFERRED_ACCEPT
#define HAVE_DEFERRED_ACCEPT  1
#endif


#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  0
#endif


#ifndef HAVE_SELECT_CHANGE_TIMEOUT
#define HAVE_SELECT_CHANGE_TIMEOUT   1
#endif


#define ngx_setproctitle(title)


#endif /* _NGX_LINUX_CONFIG_H_INCLUDED_ */
