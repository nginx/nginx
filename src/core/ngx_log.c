
/*
   TODO: log pid and tid
*/

/*
   "[time as ctime()] [alert] 412#3 (32)Broken pipe: anything"

   "[time as ctime()] [alert] (32)Broken pipe: anything"
   "[time as ctime()] [alert] anything"
*/

#include <ngx_config.h>
#include <ngx_core.h>


static const char *err_levels[] = {
    "stderr", "emerg", "alert", "crit", "error",
    "warn", "notice", "info", "debug"
};

#if (HAVE_VARIADIC_MACROS)
void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...)
#else
void ngx_log_error_core(int level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, va_list args)
#endif
{
    char      errstr[MAX_ERROR_STR];
    ngx_tm_t  tm;
    size_t    len;
#if (HAVE_VARIADIC_MACROS)
    va_list   args;
#endif

    ngx_localtime(&tm);
    len = ngx_snprintf(errstr, sizeof(errstr), "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                       tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                        " [%s] ", err_levels[level]);

    /* pid#tid */
    len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                        "%d#%d: ", ngx_getpid(), 0);

#if (HAVE_VARIADIC_MACROS)
    va_start(args, fmt);
    len += ngx_vsnprintf(errstr + len, sizeof(errstr) - len - 1, fmt, args);
    va_end(args);
#else
    len += ngx_vsnprintf(errstr + len, sizeof(errstr) - len - 1, fmt, args);
#endif

    if (err) {

#if (WIN32)
        if ((unsigned) err >= 0x80000000) {
            len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                                " (%X: ", err);
        } else {
            len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                                " (%d: ", err);
        }
#else
        len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                            " (%d: ", err);
#endif

        len += ngx_strerror_r(err, errstr + len, sizeof(errstr) - len - 1);
        if (len < sizeof(errstr) - 2) {
            errstr[len++] = ')';
        } else {
            len = sizeof(errstr) - 2;
        }
    }

    if (level != NGX_LOG_DEBUG && log->handler) {
        len += log->handler(log->data, errstr + len, sizeof(errstr) - len - 1);
    }

    if (len > sizeof(errstr) - 2) {
        len = sizeof(errstr) - 2;
    }

#if (WIN32)
    errstr[len++] = '\r';
#endif
    errstr[len++] = '\n';

    write(log->fd, errstr, len);

#if 0
    errstr[len] = '\0';
    fputs(errstr, stderr);
    fflush(stderr);
#endif
}


#if !(HAVE_VARIADIC_MACROS)

void ngx_log_error(int level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...)
{
    va_list    args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        ngx_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void ngx_log_debug_core(ngx_log_t *log, const char *fmt, ...)
{
    va_list    args;

    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_DEBUG, log, 0, fmt, args);
    va_end(args);
}


void ngx_assert_core(ngx_log_t *log, const char *fmt, ...)
{
    va_list    args;

    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_ALERT, log, 0, fmt, args);
    va_end(args);
}

#endif


void ngx_log_stderr(ngx_event_t *ev)
{
    char       errstr[MAX_ERROR_STR];
    ssize_t    n;
    ngx_err_t  err;

    for ( ;; ) {
        n = read((ngx_fd_t) ev->data, errstr, sizeof(errstr - 1));

        if (n == -1) {
            err = ngx_errno;            
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, &ngx_log, err, "read() failed");
            return;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ALERT, &ngx_log, 0, "stderr clolsed");
            return;
        }

        errstr[n] = '\0';
        ngx_log_error(NGX_LOG_STDERR, &ngx_log, 0, "%s", errstr);
    }
}
