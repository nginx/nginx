
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SOLARIS_CONFIG_H_INCLUDED_
#define _NGX_SOLARIS_CONFIG_H_INCLUDED_


#define SOLARIS  1

#define _REENTRANT

#define _FILE_OFFSET_BITS  64   /* must be before <sys/types.h> */

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

#include <sys/sendfile.h>
#include <sys/systeminfo.h>
#include <limits.h>             /* IOV_MAX */
#include <inttypes.h>

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


#if (HAVE_AIO)
#include <aio.h>
#endif


#if (HAVE_DEVPOLL)
#include <sys/ioctl.h>
#include <sys/devpoll.h>
#endif


#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif


#define ngx_setproctitle(title)


#endif /* _NGX_SOLARIS_CONFIG_H_INCLUDED_ */
