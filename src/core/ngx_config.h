#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_


#include <ngx_auto_config.h>


#if defined __FreeBSD__
#include <ngx_freebsd_config.h>


#elif defined __linux__
#include <ngx_linux_config.h>


       /* Solaris */
#elif defined(sun) && (defined(__svr4__) || defined(__SVR4))
#include <ngx_solaris_config.h>


#elif defined _WIN32

/* STUB to allocate a big ngx_connections */
#undef  FD_SETSIZE
#define FD_SETSIZE  1024

#include <ngx_win32_config.h>


#else /* posix */

#endif



/* TODO: platform specific: array[NGX_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NGX_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto_conf */
#define NGX_ALIGN       (4 - 1)
#define NGX_ALIGN_TYPE  (unsigned int)

#define ngx_align(p)    (char *) ((NGX_ALIGN_TYPE p + NGX_ALIGN) & ~NGX_ALIGN)


/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline   inline
#endif


#ifndef INFTIM    /* Linux */
#define INFTIM    -1
#endif

#ifndef INADDR_NONE    /* Solaris */
#define INADDR_NONE ((unsigned long) -1)
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif


#endif /* _NGX_CONFIG_H_INCLUDED_ */
