#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_THREADS)

#if (USE_RFORK)

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sched.h>

typedef pid_t  ngx_tid_t;

#define TID_T_FMT      PID_T_FMT

#define ngx_log_tid    0

#undef ngx_log_pid
#define ngx_log_pid    ngx_thread_self()


#define NGX_MUTEX_LIGHT      1
#define NGX_MUTEX_CV         2

#define NGX_MUTEX_LOCK_BUSY  0x80000000

typedef volatile struct {
    ngx_atomic_t  lock;
    ngx_log_t    *log;
    int           semid;
} ngx_mutex_t;


#else /* use pthreads */

#include <pthread.h>

typedef pthread_t  ngx_tid_t;

#define ngx_log_tid    ngx_thread_self()

#endif


ngx_int_t ngx_init_threads(int n, size_t size, ngx_log_t *log);
int ngx_create_thread(ngx_tid_t *tid, int (*func)(void *arg), void *arg,
                      ngx_log_t *log);
ngx_tid_t ngx_thread_self();

ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, uint flags);
void ngx_mutex_done(ngx_mutex_t *m);

#define ngx_mutex_trylock(m)  ngx_mutex_do_lock(m, 1)
#define ngx_mutex_lock(m)     ngx_mutex_do_lock(m, 0)
ngx_int_t ngx_mutex_do_lock(ngx_mutex_t *m, ngx_int_t try);
ngx_int_t ngx_mutex_unlock(ngx_mutex_t *m);


#else /* !NGX_THREADS */

#define ngx_log_tid  0
#define TID_T_FMT    "%d"

#define ngx_mutex_lock(m)
#define ngx_mutex_unlock(m)

#endif


#endif /* _NGX_THREAD_H_INCLUDED_ */
