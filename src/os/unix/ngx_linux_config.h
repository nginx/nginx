#ifndef _NGX_LINUX_CONFIG_H_INCLUDED_
#define _NGX_LINUX_CONFIG_H_INCLUDED_


#define _GNU_SOURCE             /* pread, pwrite, gethostname, bzero */

#define _FILE_OFFSET_BITS  64
#define _LARGEFILE_SOURCE


#include <unistd.h>
#include <stddef.h>             /* offsetof */
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>



#define OFF_FMT    "%lld"
#define SIZE_FMT   "%d"
#define SIZEX_FMT  "%x"
#define TIME_FMT   "%ld"
#define PID_FMT    "%d"
#define RLIM_FMT   "%lu"



#ifndef HAVE_SELECT
#define HAVE_SELECT  1
#endif


#ifndef HAVE_POLL
#define HAVE_POLL  1
#endif
#if (HAVE_POLL)
#include <poll.h>
#endif


#if defined TCP_DEFER_ACCEPT && !defined HAVE_DEFERRED_ACCEPT
#define HAVE_DEFERRED_ACCEPT  1
#endif


#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif


#ifndef HAVE_FIONBIO
#define HAVE_FIONBIO   1
#endif


#ifndef HAVE_SELECT_CHANGE_TIMEOUT
#define HAVE_SELECT_CHANGE_TIMEOUT   1
#endif


#endif /* _NGX_LINUX_CONFIG_H_INCLUDED_ */
