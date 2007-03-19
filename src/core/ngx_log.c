
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


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
    NGX_MODULE_V1,
    &ngx_errlog_module_ctx,                /* module context */
    ngx_errlog_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_log_t        ngx_log;
static ngx_open_file_t  ngx_stderr;


static const char *err_levels[] = {
    "stderr", "emerg", "alert", "crit", "error",
    "warn", "notice", "info", "debug"
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_mysql"
};


#if (NGX_HAVE_VARIADIC_MACROS)

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)

#else

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (NGX_HAVE_VARIADIC_MACROS)
    va_list  args;
#endif
    u_char   errstr[NGX_MAX_ERROR_STR], *p, *last;

    if (log->file->fd == NGX_INVALID_FILE) {
        return;
    }

    last = errstr + NGX_MAX_ERROR_STR;

    ngx_memcpy(errstr, ngx_cached_err_log_time.data,
               ngx_cached_err_log_time.len);

    p = errstr + ngx_cached_err_log_time.len;

    p = ngx_snprintf(p, last - p, " [%s] ", err_levels[level]);

    /* pid#tid */
    p = ngx_snprintf(p, last - p, "%P#" NGX_TID_T_FMT ": ",
                    ngx_log_pid, ngx_log_tid);

    if (log->connection) {
        p = ngx_snprintf(p, last - p, "*%uA ", log->connection);
    }

#if (NGX_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = ngx_vsnprintf(p, last - p, fmt, args);
    va_end(args);

#else

    p = ngx_vsnprintf(p, last - p, fmt, args);

#endif

    if (err) {

        if (p > last - 50) {

            /* leave a space for an error code */

            p = last - 50;
            *p++ = '.';
            *p++ = '.';
            *p++ = '.';
        }

#if (NGX_WIN32)

        if ((unsigned) err >= 0x80000000) {
            p = ngx_snprintf(p, last - p, " (%Xd: ", err);

        } else {
            p = ngx_snprintf(p, last - p, " (%d: ", err);
        }

#else

        p = ngx_snprintf(p, last - p, " (%d: ", err);

#endif

        p = ngx_strerror_r(err, p, last - p);

        if (p < last) {
            *p++ = ')';
        }
    }

    if (level != NGX_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    ngx_linefeed(p);

    ngx_write_fd(log->file->fd, errstr, p - errstr);
}


#if !(NGX_HAVE_VARIADIC_MACROS)

void ngx_cdecl
ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        ngx_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void ngx_cdecl
ngx_log_debug_core(ngx_log_t *log, ngx_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


void
ngx_log_abort(ngx_err_t err, const char *text)
{
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err, text);
}


ngx_log_t *
ngx_log_init(void)
{
    ngx_log.file = &ngx_stderr;
    ngx_log.log_level = NGX_LOG_NOTICE;

#if (NGX_WIN32)

    ngx_stderr_fileno = GetStdHandle(STD_ERROR_HANDLE);

    ngx_stderr.fd = ngx_open_file(NGX_ERROR_LOG_PATH, NGX_FILE_RDWR,
                                  NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND, 0);

    if (ngx_stderr.fd == NGX_INVALID_FILE) {
        ngx_message_box("nginx", MB_OK, ngx_errno,
                        "Could not open error log file: "
                        ngx_open_file_n " \"" NGX_ERROR_LOG_PATH "\" failed");
        return NULL;
    }

    if (ngx_file_append_mode(ngx_stderr.fd) == NGX_ERROR) {
        ngx_message_box("nginx", MB_OK, ngx_errno,
                        "Could not open error log file: "
                        ngx_file_append_mode_n " \"" NGX_ERROR_LOG_PATH
                        "\" failed");
        return NULL;
    }

#else

    ngx_stderr.fd = STDERR_FILENO;

#endif

    return &ngx_log;
}


ngx_log_t *
ngx_log_create_errlog(ngx_cycle_t *cycle, ngx_array_t *args)
{
    ngx_log_t  *log;
    ngx_str_t  *value, *name;

    if (args) {
        value = args->elts;
        name = &value[1];

    } else {
        name = NULL;
    }

    log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->file = ngx_conf_open_file(cycle, name);
    if (log->file == NULL) {
        return NULL;
    }

    return log;
}


char *
ngx_set_error_log_levels(ngx_conf_t *cf, ngx_log_t *log)
{
    ngx_uint_t   i, n, d;
    ngx_str_t   *value;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            if (ngx_strcmp(value[i].data, err_levels[n]) == 0) {

                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%s\"",
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


static char *
ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
