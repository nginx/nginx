#ifndef _NGX_LOG_H_INCLUDED_
#define _NGX_LOG_H_INCLUDED_


#include <ngx_errno.h>

typedef enum {
    NGX_LOG_EMERG = 0,
    NGX_LOG_ALERT,
    NGX_LOG_CRIT,
    NGX_LOG_ERR,
    NGX_LOG_WARN,
    NGX_LOG_NOTICE,
    NGX_LOG_INFO,
    NGX_LOG_DEBUG
} ngx_log_e;

/*
    "... while ", action = "reading client request headers"
    "... while reading client request headers"
    "... while ", action = "reading client request headers"
                  context: pop3 user account
    "... while reading client command for 'john_doe'"
*/

typedef struct {
    int    log_level;
    char  *action;
    char  *context;
/*  char  *func(ngx_log_t *log); */
} ngx_log_t;

#define MAX_ERROR_STR	2048

#define _               ,


#if (HAVE_GCC_VARIADIC_MACROS)

#define HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, args...) \
        if (log->log_level >= level) ngx_log_error_core(level, log, args)

#ifdef NGX_DEBUG
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

#ifdef NGX_DEBUG
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

#ifdef NGX_DEBUG
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


#endif /* _NGX_LOG_H_INCLUDED_ */
