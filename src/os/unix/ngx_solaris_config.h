#ifndef _NGX_SOLARIS_CONFIG_H_INCLUDED_
#define _NGX_SOLARIS_CONFIG_H_INCLUDED_


#define SOLARIS  1

#define _REENTRANT

#define _FILE_OFFSET_BITS  64   /* must be before sys/types.h */

#include <unistd.h>
#include <stddef.h>             /* offsetof */
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/filio.h>          /* FIONBIO */
#include <sys/stropts.h>        /* INFTIM */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


typedef uint32_t  u_int32_t;

#define OFF_FMT    "%lld"
#define SIZE_FMT   "%d"
#define SIZEX_FMT  "%x"
#define PID_FMT    "%ld"


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


#endif /* _NGX_SOLARIS_CONFIG_H_INCLUDED_ */
