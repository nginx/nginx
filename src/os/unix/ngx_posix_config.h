
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_POSIX_CONFIG_H_INCLUDED_
#define _NGX_POSIX_CONFIG_H_INCLUDED_


#if (NGX_HPUX)
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED  1
#endif


#if (NGX_TRU64)
#define _REENTRANT
#endif


#ifdef __CYGWIN__
#define timezonevar             /* timezone is variable */
#define NGX_BROKEN_SCM_RIGHTS   1
#endif


#include <sys/types.h>
#include <sys/time.h>
#if (NGX_HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if (NGX_HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
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
#include <glob.h>
#if (NGX_HAVE_SYS_PARAM_H)
#include <sys/param.h>          /* statfs() */
#endif
#if (NGX_HAVE_SYS_MOUNT_H)
#include <sys/mount.h>          /* statfs() */
#endif
#if (NGX_HAVE_SYS_STATVFS_H)
#include <sys/statvfs.h>        /* statvfs() */
#endif

#if (NGX_HAVE_SYS_FILIO_H)
#include <sys/filio.h>          /* FIONBIO */
#endif
#include <sys/ioctl.h>          /* FIONBIO */

#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sched.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        /* TCP_NODELAY */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>

#if (NGX_HAVE_LIMITS_H)
#include <limits.h>             /* IOV_MAX */
#endif

#ifdef __CYGWIN__
#include <malloc.h>             /* memalign() */
#endif

#if (NGX_HAVE_CRYPT_H)
#include <crypt.h>
#endif


#ifndef IOV_MAX
#define IOV_MAX   16
#endif


#include <ngx_auto_config.h>


#if (NGX_HAVE_POSIX_SEM)
#include <semaphore.h>
#endif


#if (NGX_HAVE_POLL)
#include <poll.h>
#endif


#if (NGX_HAVE_KQUEUE)
#include <sys/event.h>
#endif


#if (NGX_HAVE_DEVPOLL)
#include <sys/ioctl.h>
#include <sys/devpoll.h>
#endif


#if (NGX_HAVE_FILE_AIO)
#include <aio.h>
typedef struct aiocb  ngx_aiocb_t;
#endif


#define NGX_LISTEN_BACKLOG  511


#if (__FreeBSD__) && (__FreeBSD_version < 400017)

#include <sys/param.h>          /* ALIGN() */

/*
 * FreeBSD 3.x has no CMSG_SPACE() and CMSG_LEN() and has the broken CMSG_DATA()
 */

#undef  CMSG_SPACE
#define CMSG_SPACE(l)       (ALIGN(sizeof(struct cmsghdr)) + ALIGN(l))

#undef  CMSG_LEN
#define CMSG_LEN(l)         (ALIGN(sizeof(struct cmsghdr)) + (l))

#undef  CMSG_DATA
#define CMSG_DATA(cmsg)     ((u_char *)(cmsg) + ALIGN(sizeof(struct cmsghdr)))

#endif


extern char **environ;


#endif /* _NGX_POSIX_CONFIG_H_INCLUDED_ */
