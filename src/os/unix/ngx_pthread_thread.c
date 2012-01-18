
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_uint_t   nthreads;
static ngx_uint_t   max_threads;


static pthread_attr_t  thr_attr;


ngx_err_t
ngx_create_thread(ngx_tid_t *tid, ngx_thread_value_t (*func)(void *arg),
    void *arg, ngx_log_t *log)
{
    int  err;

    if (nthreads >= max_threads) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "no more than %ui threads can be created", max_threads);
        return NGX_ERROR;
    }

    err = pthread_create(tid, &thr_attr, func, arg);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "pthread_create() failed");
        return err;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                   "thread is created: " NGX_TID_T_FMT, *tid);

    nthreads++;

    return err;
}


ngx_int_t
ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle)
{
    int  err;

    max_threads = n;

    err = pthread_attr_init(&thr_attr);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      "pthread_attr_init() failed");
        return NGX_ERROR;
    }

    err = pthread_attr_setstacksize(&thr_attr, size);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      "pthread_attr_setstacksize() failed");
        return NGX_ERROR;
    }

    ngx_threaded = 1;

    return NGX_OK;
}


ngx_mutex_t *
ngx_mutex_init(ngx_log_t *log, ngx_uint_t flags)
{
    int           err;
    ngx_mutex_t  *m;

    m = ngx_alloc(sizeof(ngx_mutex_t), log);
    if (m == NULL) {
        return NULL;
    }

    m->log = log;

    err = pthread_mutex_init(&m->mutex, NULL);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_init() failed");
        return NULL;
    }

    return m;
}


void
ngx_mutex_destroy(ngx_mutex_t *m)
{
    int  err;

    err = pthread_mutex_destroy(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_destroy(%p) failed", m);
    }

    ngx_free(m);
}


void
ngx_mutex_lock(ngx_mutex_t *m)
{
    int  err;

    if (!ngx_threaded) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "lock mutex %p", m);

    err = pthread_mutex_lock(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_lock(%p) failed", m);
        ngx_abort();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is locked", m);

    return;
}


ngx_int_t
ngx_mutex_trylock(ngx_mutex_t *m)
{
    int  err;

    if (!ngx_threaded) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "try lock mutex %p", m);

    err = pthread_mutex_trylock(&m->mutex);

    if (err == NGX_EBUSY) {
        return NGX_AGAIN;
    }

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_trylock(%p) failed", m);
        ngx_abort();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is locked", m);

    return NGX_OK;
}


void
ngx_mutex_unlock(ngx_mutex_t *m)
{
    int  err;

    if (!ngx_threaded) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "unlock mutex %p", m);

    err = pthread_mutex_unlock(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_unlock(%p) failed", m);
        ngx_abort();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is unlocked", m);

    return;
}


ngx_cond_t *
ngx_cond_init(ngx_log_t *log)
{
    int          err;
    ngx_cond_t  *cv;

    cv = ngx_alloc(sizeof(ngx_cond_t), log);
    if (cv == NULL) {
        return NULL;
    }

    cv->log = log;

    err = pthread_cond_init(&cv->cond, NULL);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_init() failed");
        return NULL;
    }

    return cv;
}


void
ngx_cond_destroy(ngx_cond_t *cv)
{
    int  err;

    err = pthread_cond_destroy(&cv->cond);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_destroy(%p) failed", cv);
    }

    ngx_free(cv);
}


ngx_int_t
ngx_cond_wait(ngx_cond_t *cv, ngx_mutex_t *m)
{
    int  err;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p wait", cv);

    err = pthread_cond_wait(&cv->cond, &m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_wait(%p) failed", cv);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p is waked up", cv);

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is locked", m);

    return NGX_OK;
}


ngx_int_t
ngx_cond_signal(ngx_cond_t *cv)
{
    int  err;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p to signal", cv);

    err = pthread_cond_signal(&cv->cond);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_signal(%p) failed", cv);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p is signaled", cv);

    return NGX_OK;
}
