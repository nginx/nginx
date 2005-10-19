
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_THREADS)

#define NGX_MAX_THREADS      128

#if (NGX_USE_RFORK)
#include <ngx_freebsd_rfork_thread.h>


#else /* use pthreads */

#include <pthread.h>

typedef pthread_t                    ngx_tid_t;

#define ngx_thread_self()            pthread_self()
#define ngx_log_tid                  (int) ngx_thread_self()

#if (NGX_FREEBSD) && !(NGX_LINUXTHREADS)
#define NGX_TID_T_FMT                "%p"
#else
#define NGX_TID_T_FMT                "%d"
#endif


typedef pthread_key_t                ngx_tls_key_t;

#define ngx_thread_key_create(key)   pthread_key_create(key, NULL)
#define ngx_thread_key_create_n      "pthread_key_create()"
#define ngx_thread_set_tls           pthread_setspecific
#define ngx_thread_set_tls_n         "pthread_setspecific()"
#define ngx_thread_get_tls           pthread_getspecific


#define NGX_MUTEX_LIGHT     0

typedef struct {
    pthread_mutex_t   mutex;
    ngx_log_t        *log;
} ngx_mutex_t;

typedef struct {
    pthread_cond_t    cond;
    ngx_log_t        *log;
} ngx_cond_t;

#define ngx_thread_sigmask     pthread_sigmask
#define ngx_thread_sigmask_n  "pthread_sigmask()"

#define ngx_thread_join(t, p)  pthread_join(t, p)

#define ngx_setthrtitle(n)



ngx_int_t ngx_mutex_trylock(ngx_mutex_t *m);
void ngx_mutex_lock(ngx_mutex_t *m);
void ngx_mutex_unlock(ngx_mutex_t *m);

#endif


#define ngx_thread_volatile   volatile


typedef struct {
    ngx_tid_t    tid;
    ngx_cond_t  *cv;
    ngx_uint_t   state;
} ngx_thread_t;

#define NGX_THREAD_FREE   1
#define NGX_THREAD_BUSY   2
#define NGX_THREAD_EXIT   3
#define NGX_THREAD_DONE   4

extern ngx_int_t              ngx_threads_n;
extern volatile ngx_thread_t  ngx_threads[NGX_MAX_THREADS];


typedef void *  ngx_thread_value_t;

ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle);
ngx_err_t ngx_create_thread(ngx_tid_t *tid,
    ngx_thread_value_t (*func)(void *arg), void *arg, ngx_log_t *log);

ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, ngx_uint_t flags);
void ngx_mutex_destroy(ngx_mutex_t *m);


ngx_cond_t *ngx_cond_init(ngx_log_t *log);
void ngx_cond_destroy(ngx_cond_t *cv);
ngx_int_t ngx_cond_wait(ngx_cond_t *cv, ngx_mutex_t *m);
ngx_int_t ngx_cond_signal(ngx_cond_t *cv);


#else /* !NGX_THREADS */

#define ngx_thread_volatile

#define ngx_log_tid           0
#define NGX_TID_T_FMT         "%d"

#define ngx_mutex_trylock(m)  NGX_OK
#define ngx_mutex_lock(m)
#define ngx_mutex_unlock(m)

#define ngx_cond_signal(cv)

#define ngx_thread_main()     1

#endif



#endif /* _NGX_THREAD_H_INCLUDED_ */
