
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void ngx_log_write(ngx_log_t *log, char *errstr, size_t len);
static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_errlog_commands[] = {

    {ngx_string("error_log"),
     NGX_MAIN_CONF|NGX_CONF_1MORE,
     ngx_set_error_log,
     0,
     0,
     NULL},

    ngx_null_command
};


static ngx_core_module_t  ngx_errlog_module_ctx = {
    ngx_string("errlog"),
    NULL,                           
    NULL
};


ngx_module_t  ngx_errlog_module = {
    NGX_MODULE,
    &ngx_errlog_module_ctx,                /* module context */
    ngx_errlog_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_log_t        ngx_log;
static ngx_open_file_t  ngx_stderr;


static const char *err_levels[] = {
    "stderr", "emerg", "alert", "crit", "error",
    "warn", "notice", "info", "debug"
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_imap"
};


#if (HAVE_VARIADIC_MACROS)
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...)
#else
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
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
                        PID_T_FMT "#" TID_T_FMT ": ", ngx_log_pid, ngx_log_tid);

    if (log->data && *(int *) log->data != -1) {
        len += ngx_snprintf(errstr + len, max - len,
                            "*%u ", *(u_int *) log->data);
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

void ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
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


ngx_log_t *ngx_log_init_stderr()
{
#if (WIN32)

    ngx_stderr_fileno = GetStdHandle(STD_ERROR_HANDLE);
    ngx_stderr.fd = ngx_stderr_fileno;

    if (ngx_stderr_fileno == NGX_INVALID_FILE) {

        /* TODO: where can we log error ? */

        return NULL;

    } else if (ngx_stderr_fileno == NULL) {

        /* there are no associated standard handles */

        /* TODO: where can we can log possible errors ? */

        ngx_stderr.fd = NGX_INVALID_FILE;
    }

#else

    ngx_stderr.fd = STDERR_FILENO;

#endif

    ngx_log.file = &ngx_stderr;
    ngx_log.log_level = NGX_LOG_ERR;

    return &ngx_log;
}


#if 0

ngx_int_t ngx_log_init_error_log()
{
    ngx_fd_t  fd;

#ifdef NGX_ERROR_LOG_PATH

    fd = ngx_open_file(NGX_ERROR_LOG_PATH, NGX_FILE_RDWR,
                       NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, (&ngx_log), ngx_errno,
                      ngx_open_file_n " \"" NGX_ERROR_LOG_PATH "\" failed");
        return NGX_ERROR;
    }

#if (WIN32)

    if (ngx_file_append_mode(fd) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, (&ngx_log), ngx_errno,
                      ngx_file_append_mode_n " \"" NGX_ERROR_LOG_PATH
                      "\" failed");
        return NGX_ERROR;
    }

#else

    if (dup2(fd, STDERR_FILENO) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, (&ngx_log), ngx_errno,
                      "dup2(STDERR) failed");
        return NGX_ERROR;
    }

#endif

#else  /* no NGX_ERROR_LOG_PATH */

    ngx_log.log_level = NGX_LOG_INFO;

#endif

    return NGX_OK;
}

#endif


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

    if (!(log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t)))) {
        return NULL;
    }

    if (!(log->file = ngx_conf_open_file(cycle, name))) {
        return NULL;
    }

    return log;
}


char *ngx_set_error_log_levels(ngx_conf_t *cf, ngx_log_t *log)
{
    ngx_uint_t   i, n, d;
    ngx_str_t   *value;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
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

    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    }

    return NGX_CONF_OK;
}


static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value;

    value = cf->args->elts;

    if (value[1].len == 6 && ngx_strcmp(value[1].data, "stderr") == 0) {
        cf->cycle->new_log->file->fd = ngx_stderr.fd;
        cf->cycle->new_log->file->name.len = 0;
        cf->cycle->new_log->file->name.data = NULL;

    } else {
        cf->cycle->new_log->file->name = value[1];

        if (ngx_conf_full_name(cf->cycle, &cf->cycle->new_log->file->name)
                                                                  == NGX_ERROR)
        {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_set_error_log_levels(cf, cf->cycle->new_log);
}
