#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


#define WIN32 1

#include <winsock2.h>
#include <mswsock.h>
#include <stddef.h>    /* offsetof */
#include <stdio.h>
#include <stdarg.h>


#define ngx_inline   __inline


#ifndef HAVE_INHERITED_NONBLOCK
#define HAVE_INHERITED_NONBLOCK  1
#endif

#ifndef HAVE_WIN32_TRANSMITPACKETS
#define HAVE_WIN32_TRANSMITPACKETS  1
#define HAVE_WIN32_TRANSMITFILE     0
#endif

#ifndef HAVE_WIN32_TRANSMITFILE
#define HAVE_WIN32_TRANSMITFILE  1
#endif

#if (HAVE_WIN32_TRANSMITPACKETS) || (HAVE_WIN32_TRANSMITFILE)
#define HAVE_SENDFILE  1
#endif


#endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
