
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_FREEBSD_RFORK_THREAD_H_INCLUDED_
#define _NGX_FREEBSD_RFORK_THREAD_H_INCLUDED_


#include <sys/ipc.h>
#include <sys/sem.h>
#include <sched.h>

typedef pid_t  ngx_tid_t;

#undef ngx_log_pid
#define ngx_log_pid    ngx_thread_self()
#define ngx_log_tid    0

#define TID_T_FMT      PID_T_FMT


#define NGX_MUTEX_LIGHT      1

#define NGX_MUTEX_LOCK_BUSY  0x80000000

typedef volatile struct {
    ngx_atomic_t  lock;
    ngx_log_t    *log;
    int           semid;
} ngx_mutex_t;


#define NGX_CV_SIGNAL        64

typedef struct {
    int           signo;
    int           kq;
    ngx_tid_t     tid;
    ngx_log_t    *log;
} ngx_cond_t;


#define ngx_thread_sigmask(how, set, oset)                         \
            (sigprocmask(how, set, oset) == -1) ? ngx_errno : 0

#define ngx_thread_sigmask_n   "sigprocmask()"

#define ngx_thread_join(t, p)

#define ngx_setthrtitle(n)     setproctitle(n)


extern char    *ngx_freebsd_kern_usrstack;
extern size_t   ngx_thread_stack_size;


static inline int ngx_gettid()
{
    char  *sp;

    if (ngx_thread_stack_size == 0) {
        return 0;
    }

#if ( __i386__ )

    __asm__ volatile ("mov %%esp, %0" : "=q" (sp));

#elif ( __amd64__ )

    __asm__ volatile ("mov %%rsp, %0" : "=q" (sp));

#else

#error "rfork()ed threads are not supported on this platform"

#endif

    return (ngx_freebsd_kern_usrstack - sp) / ngx_thread_stack_size;
}


ngx_tid_t ngx_thread_self();


typedef ngx_uint_t               ngx_tls_key_t;

#define NGX_THREAD_KEYS_MAX      16

extern void    **ngx_tls;

ngx_int_t ngx_thread_key_create(ngx_tls_key_t *key);
#define ngx_thread_key_create_n  "the tls key creation"

ngx_int_t ngx_thread_set_tls(ngx_tls_key_t key, void *value);
#define ngx_thread_set_tls_n     "the tls key setting"


static void *ngx_thread_get_tls(ngx_tls_key_t key)
{   
    if (key >= NGX_THREAD_KEYS_MAX) {
        return NULL;
    }

    return ngx_tls[key * NGX_THREAD_KEYS_MAX + ngx_gettid()];
}


#define ngx_mutex_trylock(m)  ngx_mutex_dolock(m, 1)
#define ngx_mutex_lock(m)     ngx_mutex_dolock(m, 0)
ngx_int_t ngx_mutex_dolock(ngx_mutex_t *m, ngx_int_t try);
ngx_int_t ngx_mutex_unlock(ngx_mutex_t *m);


typedef int (*ngx_rfork_thread_func_pt)(void *arg);



#endif /* _NGX_FREEBSD_RFORK_THREAD_H_INCLUDED_ */
