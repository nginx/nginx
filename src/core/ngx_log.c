
#include <ngx_config.h>
#include <ngx_core.h>


static void ngx_log_write(ngx_log_t *log, char *errstr, size_t len);
static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_str_t  errlog_name = ngx_string("errlog");

static ngx_command_t  ngx_errlog_commands[] = {

    {ngx_string("error_log"),
     NGX_MAIN_CONF|NGX_CONF_1MORE,
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

static const char *debug_levels[] = {
    "debug", "debug_core", "debug_alloc", "debug_event", "debug_http"
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
    size_t    len, max;
#if (HAVE_VARIADIC_MACROS)
    va_list   args;
#endif

    if (log->file->fd == NGX_INVALID_FILE) {
        return;
    }

    ngx_memcpy(errstr, ngx_cached_err_log_time.data,
               ngx_cached_err_log_time.len);

#if (WIN32)
    max = MAX_ERROR_STR - 2;
#else
    max = MAX_ERROR_STR - 1;
#endif

    len = ngx_cached_err_log_time.len;

    len += ngx_snprintf(errstr + len, max - len, " [%s] ", err_levels[level]);

    /* pid#tid */
    len += ngx_snprintf(errstr + len, max - len,
                        PID_T_FMT "#%d: ", ngx_getpid(), /* STUB */ 0);

    if (log->data) {
        len += ngx_snprintf(errstr + len, max - len,
                            "*%u ", * (u_int *) log->data);
    }

#if (HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    len += ngx_vsnprintf(errstr + len, max - len, fmt, args);
    va_end(args);

#else

    len += ngx_vsnprintf(errstr + len, max - len, fmt, args);

#endif

    if (err) {

        if (len > max - 50) {
            /* leave a space for an error code */
            len = max - 50;
            errstr[len++] = '.';
            errstr[len++] = '.';
            errstr[len++] = '.';
        }

#if (WIN32)
        if ((unsigned) err >= 0x80000000) {
            len += ngx_snprintf(errstr + len, max - len, " (%X: ", err);
        } else {
            len += ngx_snprintf(errstr + len, max - len, " (%d: ", err);
        }
#else
        len += ngx_snprintf(errstr + len, max - len, " (%d: ", err);
#endif

        if (len >= max) {
            ngx_log_write(log, errstr, max);
            return;
        }

        len += ngx_strerror_r(err, errstr + len, max - len);

        if (len >= max) {
            ngx_log_write(log, errstr, max);
            return;
        }

        errstr[len++] = ')';

        if (len >= max) {
            ngx_log_write(log, errstr, max);
            return;
        }

    } else {
        if (len >= max) {
            ngx_log_write(log, errstr, max);
            return;
        }
    }

    if (level != NGX_LOG_DEBUG && log->handler) {
        len += log->handler(log->data, errstr + len, max - len);

        if (len >= max) {
            len = max;
        }
    }

    ngx_log_write(log, errstr, len);
}


static void ngx_log_write(ngx_log_t *log, char *errstr, size_t len)
{
#if (WIN32)
    u_long  written;

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


ngx_log_t *ngx_log_create_errlog(ngx_cycle_t *cycle, ngx_array_t *args)
{
    ngx_log_t  *log;
    ngx_str_t  *value, *name;

    if (args) {
        value = args->elts;
        name = &value[1];

    } else {
        name = NULL;
    }

    ngx_test_null(log, ngx_pcalloc(cycle->pool, sizeof(ngx_log_t)), NULL);
    ngx_test_null(log->file, ngx_conf_open_file(cycle, name), NULL);

#if 0
    /* STUB */ log->log_level = NGX_LOG_DEBUG | NGX_LOG_DEBUG_CORE | NGX_LOG_DEBUG_ALLOC | NGX_LOG_DEBUG_EVENT | NGX_LOG_DEBUG_HTTP;
#endif

    return log;
}


static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value;

    value = cf->args->elts;

    if (value[1].len == 6 && ngx_strcmp(value[1].data, "stderr") == 0) {
        cf->cycle->log->file = &ngx_stderr;

    } else {
        cf->cycle->log->file->name = value[1];
    }

    return ngx_set_error_log_levels(cf, cf->cycle->log);
}


char *ngx_set_error_log_levels(ngx_conf_t *cf, ngx_log_t *log)
{
    ngx_int_t   i, n, d;
    ngx_str_t  *value;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        for (n = 1; n < NGX_LOG_DEBUG; n++) {
            if (ngx_strcmp(value[i].data, err_levels[n]) == 0) {

                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%s\"",
                                       value[i].data);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;
                continue;
            }
        }

        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%s\"",
                                       value[i].data);
                    return NGX_CONF_ERROR;
                }

                log->log_level |= d;
            }
        }


        if (log->log_level == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
