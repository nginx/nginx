#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_


#if 0
/* STUB to allocate a big ngx_connections */
#undef  FD_SETSIZE
#define FD_SETSIZE  5000
#endif


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

#include <ngx_auto_config.h>

#endif


/* STUB: autoconf */
typedef int    ngx_int_t;
typedef u_int  ngx_uint_t;


typedef int    ngx_flag_t;


#ifndef NGX_SERVER_ROOT
#define NGX_SERVER_ROOT   "./"
#if 0
#define NGX_SERVER_ROOT   "/usr/local/nginx/"
#endif
#endif


#if !(WIN32)

#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)

/* TODO: #ifndef */
#define NGX_SHUTDOWN_SIGNAL      QUIT
#define NGX_TERMINATE_SIGNAL     TERM
#define NGX_NOACCEPT_SIGNAL      WINCH
#define NGX_RECONFIGURE_SIGNAL   HUP
#define NGX_REOPEN_SIGNAL        USR1
#define NGX_CHANGEBIN_SIGNAL     USR2

#endif



/* TODO: platform specific: array[NGX_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NGX_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto */
#define NGX_INT32_LEN      sizeof("-2147483648") - 1
#define NGX_TIME_T_LEN     sizeof("-2147483648") - 1
#define NGX_OFF_T_LEN      sizeof("-9223372036854775808") - 1



/* TODO: auto_conf */
#define NGX_ALIGN       (sizeof(unsigned long) - 1)  /* platform word */
#define NGX_ALIGN_CAST  (unsigned long)              /* size of the pointer */

#define ngx_align(p)    (char *) ((NGX_ALIGN_CAST p + NGX_ALIGN) & ~NGX_ALIGN)


/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline   inline
#endif


#ifndef INFTIM  /* Linux */
#define INFTIM  -1
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifndef INET_ADDRSTRLEN  /* Win32 */
#define INET_ADDRSTRLEN  16
#endif


#endif /* _NGX_CONFIG_H_INCLUDED_ */
