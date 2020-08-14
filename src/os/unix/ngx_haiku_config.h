
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HAIKU_CONFIG_H_INCLUDED_
#define _NGX_HAIKU_CONFIG_H_INCLUDED_

#define _FILE_OFFSET_BITS       64

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>             /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <glob.h>
#include <time.h>
#include <sys/param.h>          /* statfs() */
#include <sys/statvfs.h>        /* statvfs() */
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

#include <dlfcn.h>
#include <semaphore.h>

#include <limits.h>             /* IOV_MAX */
#include <poll.h>

#ifndef IOV_MAX
#define IOV_MAX   16
#endif

#define SIGIO SIGPOLL

#include <ngx_auto_config.h>

#define NGX_LISTEN_BACKLOG  511

#define ngx_debug_init()


extern char **environ;


#endif /* _NGX_HAIKU_CONFIG_H_INCLUDED_ */
