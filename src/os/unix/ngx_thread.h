
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_THREADS)

#include <pthread.h>


typedef pthread_mutex_t  ngx_thread_mutex_t;

ngx_int_t ngx_thread_mutex_create(ngx_thread_mutex_t *mtx, ngx_log_t *log);
ngx_int_t ngx_thread_mutex_destroy(ngx_thread_mutex_t *mtx, ngx_log_t *log);
ngx_int_t ngx_thread_mutex_lock(ngx_thread_mutex_t *mtx, ngx_log_t *log);
ngx_int_t ngx_thread_mutex_unlock(ngx_thread_mutex_t *mtx, ngx_log_t *log);


typedef pthread_cond_t  ngx_thread_cond_t;

ngx_int_t ngx_thread_cond_create(ngx_thread_cond_t *cond, ngx_log_t *log);
ngx_int_t ngx_thread_cond_destroy(ngx_thread_cond_t *cond, ngx_log_t *log);
ngx_int_t ngx_thread_cond_signal(ngx_thread_cond_t *cond, ngx_log_t *log);
ngx_int_t ngx_thread_cond_wait(ngx_thread_cond_t *cond, ngx_thread_mutex_t *mtx,
    ngx_log_t *log);


#if (NGX_LINUX)

typedef pid_t      ngx_tid_t;
#define NGX_TID_T_FMT         "%P"

#elif (NGX_FREEBSD)

typedef uint32_t   ngx_tid_t;
#define NGX_TID_T_FMT         "%uD"

#elif (NGX_DARWIN)

typedef uint64_t   ngx_tid_t;
#define NGX_TID_T_FMT         "%uL"

#else

typedef uint64_t   ngx_tid_t;
#define NGX_TID_T_FMT         "%uL"

#endif

ngx_tid_t ngx_thread_tid(void);

#define ngx_log_tid           ngx_thread_tid()

#else

#define ngx_log_tid           0
#define NGX_TID_T_FMT         "%d"

#endif


#endif /* _NGX_THREAD_H_INCLUDED_ */
