#ifndef _NGX_SOLARIS_CONFIG_H_INCLUDED_
#define _NGX_SOLARIS_CONFIG_H_INCLUDED_


#define SOLARIS  1

#define _REENTRANT

#define _FILE_OFFSET_BITS  64   /* must be before sys/types.h */

#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>             /* offsetof() */
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/filio.h>          /* FIONBIO */
#include <sys/systeminfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <dirent.h>

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


#ifndef HAVE_FIONBIO
#define HAVE_FIONBIO   1
#endif


#define ngx_setproctitle(title)


/* STUB */
#define HAVE_LITTLE_ENDIAN  1


#endif /* _NGX_SOLARIS_CONFIG_H_INCLUDED_ */
