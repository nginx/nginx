#ifndef _NGX_LINUX_CONFIG_H_INCLUDED_
#define _NGX_LINUX_CONFIG_H_INCLUDED_


#define _XOPEN_SOURCE 500


#include <unistd.h>
#include <stddef.h>             /* offsetof */
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#define __USE_BSD
#include <string.h>
#undef  __USE_BSD

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


typedef unsigned int   u_int;
typedef unsigned char  u_char;


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


#endif /* _NGX_LINUX_CONFIG_H_INCLUDED_ */
