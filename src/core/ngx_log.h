#ifndef _NGX_LOG_H_INCLUDED_
#define _NGX_LOG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef enum {
    NGX_LOG_STDERR = 0,
    NGX_LOG_EMERG,
    NGX_LOG_ALERT,
    NGX_LOG_CRIT,
    NGX_LOG_ERR,
    NGX_LOG_WARN,
    NGX_LOG_NOTICE,
    NGX_LOG_INFO,
    NGX_LOG_DEBUG
} ngx_log_e;


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


typedef struct {
    int               log_level;
    ngx_open_file_t  *file;
    void             *data;
    size_t           (*handler)(void *ctx, char *buf, size_t len);

#if 0
/* STUB */
    char     *action;
    char     *context;
/* */
#endif
} ngx_log_t;

#define MAX_ERROR_STR	2048

#define _               ,


#if (HAVE_GCC_VARIADIC_MACROS)

#define HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, args...) \
        if (log->log_level >= level) ngx_log_error_core(level, log, args)

#if (NGX_DEBUG)
#define ngx_log_debug(log, args...) \
    if (log->log_level == NGX_LOG_DEBUG) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, 0, args)
#else
#define ngx_log_debug(log, args...)
#endif

#define ngx_assert(assert, fallback, log, args...) \
        if (!(assert)) { \
            if (log->log_level >= NGX_LOG_ALERT) \
                ngx_log_error_core(NGX_LOG_ALERT, log, 0, args); \
            fallback; \
        }

void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...);


#elif (HAVE_C99_VARIADIC_MACROS)

#define HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, ...) \
        if (log->log_level >= level) ngx_log_error_core(level, log, __VA_ARGS__)

#if (NGX_DEBUG)
#define ngx_log_debug(log, ...) \
    if (log->log_level == NGX_LOG_DEBUG) \
        ngx_log_error_core(NGX_LOG_DEBUG, log, 0, __VA_ARGS__)
#else
#define ngx_log_debug(log, ...)
#endif

#define ngx_assert(assert, fallback, log, ...) \
        if (!(assert)) { \
            if (log->log_level >= NGX_LOG_ALERT) \
                ngx_log_error_core(NGX_LOG_ALERT, log, 0, __VA_ARGS__); \
            fallback; \
        }

void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...);


#else /* NO VARIADIC MACROS */

#include <stdarg.h>

#if (NGX_DEBUG)
#define ngx_log_debug(log, text) \
    if (log->log_level == NGX_LOG_DEBUG) \
        ngx_log_debug_core(log, text)
#else
#define ngx_log_debug(log, text)
#endif

#define ngx_assert(assert, fallback, log, text) \
        if (!(assert)) { \
            if (log->log_level >= NGX_LOG_ALERT) \
                ngx_assert_core(log, text); \
            fallback; \
        }

void ngx_log_error(int level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...);
void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, va_list args);
void ngx_log_debug_core(ngx_log_t *log, const char *fmt, ...);
void ngx_assert_core(ngx_log_t *log, const char *fmt, ...);


#endif /* VARIADIC MACROS */


#define ngx_log_alloc_log(pool, log)  ngx_palloc(pool, log, sizeof(ngx_log_t))
#define ngx_log_copy_log(new, old)    ngx_memcpy(new, old, sizeof(ngx_log_t))

ngx_log_t *ngx_log_init_errlog();
char *ngx_log_set_errlog(ngx_conf_t *cf, ngx_command_t *cmd, ngx_log_t *log);


extern ngx_module_t  ngx_errlog_module;


#endif /* _NGX_LOG_H_INCLUDED_ */
