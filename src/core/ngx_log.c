
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


static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_str_t  errlog_name = ngx_string("errlog");

static ngx_command_t  ngx_errlog_commands[] = {

    {ngx_string("error_log"),
     NGX_MAIN_CONF|NGX_CONF_TAKE12,
     ngx_set_error_log,
     0,
     0,
     NULL},

    ngx_null_command
};


ngx_module_t  ngx_errlog_module = {
    NGX_MODULE,
    &errlog_name,                          /* module context */
    ngx_errlog_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_open_file_t  ngx_stderr;
static ngx_log_t        ngx_log;


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
    size_t    len;
#if (HAVE_VARIADIC_MACROS)
    va_list   args;
#endif
#if (WIN32)
    u_long    written;
#endif

    if (log->file->fd == NGX_INVALID_FILE) {
        return;
    }

    ngx_memcpy(errstr, ngx_cached_err_log_time.data,
               ngx_cached_err_log_time.len);

    len = ngx_cached_err_log_time.len;

#if 0
    ngx_localtime(&tm);
    len = ngx_snprintf(errstr, sizeof(errstr), "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                       tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);
#endif

    len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                        " [%s] ", err_levels[level]);

    /* pid#tid */
    len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                        PID_T_FMT "#%d: ", ngx_getpid(), 0);

    if (log->data) {
        len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                            "*%u ", * (u_int *) log->data);
    }

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

    errstr[len++] = CR;
    errstr[len++] = LF;
    WriteFile(log->file->fd, errstr, len, &written, NULL);

#else

    errstr[len++] = LF;
    write(log->file->fd, errstr, len);

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


void ngx_log_debug_core(ngx_log_t *log, ngx_err_t err, const char *fmt, ...)
{
    va_list    args;

    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, args);
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


#if 0

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

#endif



ngx_log_t *ngx_log_init_errlog()
{
#if (WIN32)

    ngx_stderr.fd = GetStdHandle(STD_ERROR_HANDLE);

    if (ngx_stderr.fd == NGX_INVALID_FILE) {
        /* TODO: where can we log error ? */
        return NULL;

    } else if (ngx_stderr.fd == NULL) {

        /* there are no associated standard handles */

        /* TODO: where can we can log possible errors ? */

        ngx_stderr.fd = NGX_INVALID_FILE;
    }

#else

    ngx_stderr.fd = STDERR_FILENO;

#endif

    ngx_log.file = &ngx_stderr;
    ngx_log.log_level = NGX_LOG_INFO;

#if 0
    /* STUB */ ngx_log.log_level = NGX_LOG_DEBUG;
#endif

    return &ngx_log;
}


ngx_log_t *ngx_log_create_errlog(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_log_t  *log;

    ngx_test_null(log, ngx_pcalloc(cycle->pool, sizeof(ngx_log_t)), NULL);
    ngx_test_null(log->file, ngx_conf_open_file(cycle, name), NULL);

#if 0
    /* STUB */ log->log_level = NGX_LOG_DEBUG;
#endif

    return log;
}


static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t   i;
    ngx_str_t  *value;

    value = cf->args->elts;

    if (value[1].len == 6 && ngx_strcmp(value[1].data, "stderr") == 0) {
        cf->cycle->log->file = &ngx_stderr;

    } else {
        cf->cycle->log->file->name = value[1];
    }

    if (cf->args->nelts == 3) {
        for (i = 1; i <= /* STUB ??? */ NGX_LOG_DEBUG; i++) {
            if (ngx_strcmp(value[2].data, err_levels[i]) == 0) {
                cf->cycle->log->log_level = i;
                break;
            }
        }
        if (i > NGX_LOG_DEBUG) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%s\"", value[2].data);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
