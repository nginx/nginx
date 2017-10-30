
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t
ngx_thread_cond_create(ngx_thread_cond_t *cond, ngx_log_t *log)
{
    ngx_err_t  err;

    err = pthread_cond_init(cond, NULL);
    if (err == 0) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_EMERG, log, err, "pthread_cond_init() failed");
    return NGX_ERROR;
}


ngx_int_t
ngx_thread_cond_destroy(ngx_thread_cond_t *cond, ngx_log_t *log)
{
    ngx_err_t  err;

    err = pthread_cond_destroy(cond);
    if (err == 0) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_EMERG, log, err, "pthread_cond_destroy() failed");
    return NGX_ERROR;
}


ngx_int_t
ngx_thread_cond_signal(ngx_thread_cond_t *cond, ngx_log_t *log)
{
    ngx_err_t  err;

    err = pthread_cond_signal(cond);
    if (err == 0) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_EMERG, log, err, "pthread_cond_signal() failed");
    return NGX_ERROR;
}


ngx_int_t
ngx_thread_cond_wait(ngx_thread_cond_t *cond, ngx_thread_mutex_t *mtx,
    ngx_log_t *log)
{
    ngx_err_t  err;

    err = pthread_cond_wait(cond, mtx);

#if 0
    ngx_time_update();
#endif

    if (err == 0) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ALERT, log, err, "pthread_cond_wait() failed");

    return NGX_ERROR;
}
