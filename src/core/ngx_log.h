#ifndef _NGX_LOG_H_INCLUDED_
#define _NGX_LOG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_LOG_STDERR          0
#define NGX_LOG_EMERG           1
#define NGX_LOG_ALERT           2
#define NGX_LOG_CRIT            3
#define NGX_LOG_ERR             4
#define NGX_LOG_WARN            5
#define NGX_LOG_NOTICE          6
#define NGX_LOG_INFO            7
#define NGX_LOG_DEBUG           8

#define NGX_LOG_DEBUG_CORE      0x10
#define NGX_LOG_DEBUG_ALLOC     0x20
#define NGX_LOG_DEBUG_EVENT     0x40
#define NGX_LOG_DEBUG_HTTP      0x80

#define NGX_LOG_DEBUG_FIRST     NGX_LOG_DEBUG_CORE
#define NGX_LOG_DEBUG_LAST      NGX_LOG_DEBUG_HTTP
#define NGX_LOG_DEBUG_ALL       0xfffffff0


/*
    "[%time] [%level] %pid#%tid: %message:(%errno)%errstr, while %action"
        " %peer and while processing %context"

    ----
    message = "recv() failed";
    errno = 32;
    action = "reading request headers from client";
    peer = "192.168.1.1";
    context = "URL /"

    "[2002/08/20 12:00:00] [error] 412#3: recv() failed (32: Broken pipe)"
    " while reading request headers from client 192.168.1.1"
    " and while processing URL /"

    ----
    message = "recv() failed";
    errno = 32;
    ngx_http_proxy_error_context_t:
        action = "reading headers from server %s for client %s and "
                 "while processing %s"
        backend = "127.0.0.1";
        peer = "192.168.1.1";
        context = "URL /"

    "[2002/08/20 12:00:00] [error] 412#3: recv() failed (32: Broken pipe)"
    " while reading headers from backend 127.0.0.1"
    " for client 192.168.1.1 and while processing URL /"

    ----
    "[alert] 412#3: ngx_alloc: malloc() 102400 bytes failed (12: Cannot "
    "allocate memory) while reading request headers from client 192.168.1.1"
    " and while processing URL /"


    OLD:
    "... while ", action = "reading client request headers"
    "... while reading client request headers"
    "... while ", action = "reading client request headers"
                  context: pop3 user account
    "... while reading client command for 'john_doe'"
*/


typedef size_t  (*ngx_log_handler_pt) (void *ctx, char *buf, size_t len);


struct ngx_log_s {
    ngx_uint_t           log_level;
    ngx_open_file_t     *file;
    void                *data;
    ngx_log_handler_pt   handler;
};

#define MAX_ERROR_STR	2048


/*********************************/

#if (HAVE_GCC_VARIADIC_MACROS)

#define HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, args...) \
        if (log->log_level >= level) ngx_log_error_core(level, log, args)

void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...);

/*********************************/

#elif (HAVE_C99_VARIADIC_MACROS)

#define HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, ...) \
        if (log->log_level >= level) ngx_log_error_core(level, log, __VA_ARGS__)

void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...);

/*********************************/

#else /* NO VARIADIC MACROS */

#define HAVE_VARIADIC_MACROS  0

void ngx_log_error(int level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...);
void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, va_list args);
void ngx_log_debug_core(ngx_log_t *log, ngx_err_t err, const char *fmt, ...);
void ngx_assert_core(ngx_log_t *log, const char *fmt, ...);


#endif /* VARIADIC MACROS */


/*********************************/

#if (HAVE_VARIADIC_MACROS)

#if (NGX_DEBUG)
#define ngx_log_debug0(level, log, err, fmt) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt)
#else
#define ngx_log_debug0(level, log, err, fmt)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug1(level, log, err, fmt, arg1) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, arg1)
#else
#define ngx_log_debug1(level, log, err, fmt, arg1)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug2(level, log, err, fmt, arg1, arg2) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, arg1, arg2)
#else
#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, arg1, arg2, arg3)
#else
#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, arg1, arg2, arg3, arg4)
#else
#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, \
                           arg1, arg2, arg3, arg4, arg5)
#else
#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug6(level, log, err, fmt, \
                       arg1, arg2, arg3, arg4, arg5, arg6) \
    if (log->log_level & level) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, \
                           arg1, arg2, arg3, arg4, arg5, arg6)
#else
#define ngx_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#endif

/*********************************/

#else /* NO VARIADIC MACROS */

#if (NGX_DEBUG)
#define ngx_log_debug0(level, log, err, fmt) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt)
#else
#define ngx_log_debug0(level, log, err, fmt)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug1(level, log, err, fmt, arg1) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt, arg1)
#else
#define ngx_log_debug1(level, log, err, fmt, arg1)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug2(level, log, err, fmt, arg1, arg2) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt, arg1, arg2)
#else
#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3)
#else
#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4)
#else
#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#else
#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#endif

#if (NGX_DEBUG)
#define ngx_log_debug6(level, log, err, fmt, \
                       arg1, arg2, arg3, arg4, arg5, arg6) \
    if (log->log_level & level) \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#else
#define ngx_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#endif

#endif


/*********************************/

#define ngx_log_alloc_log(pool, log)  ngx_palloc(pool, log, sizeof(ngx_log_t))
#define ngx_log_copy_log(new, old)    ngx_memcpy(new, old, sizeof(ngx_log_t))

ngx_log_t *ngx_log_init_errlog();
ngx_log_t *ngx_log_create_errlog(ngx_cycle_t *cycle, ngx_array_t *args);
char *ngx_set_error_log_levels(ngx_conf_t *cf, ngx_log_t *log);



extern ngx_module_t  ngx_errlog_module;


#endif /* _NGX_LOG_H_INCLUDED_ */
