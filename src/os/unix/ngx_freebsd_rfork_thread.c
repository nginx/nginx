
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * The threads implementation uses the rfork(RFPROC|RFTHREAD|RFMEM) syscall
 * to create threads.  All threads use the stacks of the same size mmap()ed
 * below the main stack.  Thus the current thread id is determined via
 * the stack pointer value.
 *
 * The mutex implementation uses the ngx_atomic_cmp_set() operation
 * to acquire a mutex and the SysV semaphore to wait on a mutex and to wake up
 * the waiting threads.  The light mutex does not use semaphore, so after
 * spinning in the lock the thread calls sched_yield().  However the light
 * mutexes are intended to be used with the "trylock" operation only.
 * The SysV semop() is a cheap syscall, particularly if it has little sembuf's
 * and does not use SEM_UNDO.
 *
 * The condition variable implementation uses the signal #64.
 * The signal handler is SIG_IGN so the kill() is a cheap syscall.
 * The thread waits a signal in kevent().  The use of the EVFILT_SIGNAL
 * is safe since FreeBSD 4.10-STABLE.
 *
 * This threads implementation currently works on i386 (486+) and amd64
 * platforms only.
 */


char                 *ngx_freebsd_kern_usrstack;
size_t                ngx_thread_stack_size;


static size_t         rz_size;
static size_t         usable_stack_size;
static char          *last_stack;

static ngx_uint_t     nthreads;
static ngx_uint_t     max_threads;

static ngx_uint_t     nkeys;
static ngx_tid_t     *tids;      /* the threads tids array */
void                **ngx_tls;   /* the threads tls's array */

/* the thread-safe libc errno */

static int   errno0;   /* the main thread's errno */
static int  *errnos;   /* the threads errno's array */

int *
__error()
{
    int  tid;

    tid = ngx_gettid();

    return tid ? &errnos[tid - 1] : &errno0;
}


/*
 * __isthreaded enables the spinlocks in some libc functions, i.e. in malloc()
 * and some other places.  Nevertheless we protect our malloc()/free() calls
 * by own mutex that is more efficient than the spinlock.
 *
 * _spinlock() is a weak referenced stub in src/lib/libc/gen/_spinlock_stub.c
 * that does nothing.
 */

extern int  __isthreaded;

void
_spinlock(ngx_atomic_t *lock)
{
    ngx_int_t  tries;

    tries = 0;

    for ( ;; ) {

        if (*lock) {
            if (ngx_ncpu > 1 && tries++ < 1000) {
                continue;
            }

            sched_yield();
            tries = 0;

        } else {
            if (ngx_atomic_cmp_set(lock, 0, 1)) {
                return;
            }
        }
    }
}


/*
 * Before FreeBSD 5.1 _spinunlock() is a simple #define in
 * src/lib/libc/include/spinlock.h that zeroes lock.
 *
 * Since FreeBSD 5.1 _spinunlock() is a weak referenced stub in
 * src/lib/libc/gen/_spinlock_stub.c that does nothing.
 */

#ifndef _spinunlock

void
_spinunlock(ngx_atomic_t *lock)
{
    *lock = 0;
}

#endif


ngx_err_t
ngx_create_thread(ngx_tid_t *tid, ngx_thread_value_t (*func)(void *arg),
    void *arg, ngx_log_t *log)
{
    ngx_pid_t   id;
    ngx_err_t   err;
    char       *stack, *stack_top;

    if (nthreads >= max_threads) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "no more than %ui threads can be created", max_threads);
        return NGX_ERROR;
    }

    last_stack -= ngx_thread_stack_size;

    stack = mmap(last_stack, usable_stack_size, PROT_READ|PROT_WRITE,
                 MAP_STACK, -1, 0);

    if (stack == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "mmap(%p:%uz, MAP_STACK) thread stack failed",
                      last_stack, usable_stack_size);
        return NGX_ERROR;
    }

    if (stack != last_stack) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "stack %p address was changed to %p", last_stack, stack);
        return NGX_ERROR;
    }

    stack_top = stack + usable_stack_size;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0,
                   "thread stack: %p-%p", stack, stack_top);

    ngx_set_errno(0);

    id = rfork_thread(RFPROC|RFTHREAD|RFMEM, stack_top,
                      (ngx_rfork_thread_func_pt) func, arg);

    err = ngx_errno;

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "rfork() failed");

    } else {
        *tid = id;
        nthreads = (ngx_freebsd_kern_usrstack - stack_top)
                                                       / ngx_thread_stack_size;
        tids[nthreads] = id;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "rfork()ed thread: %P", id);
    }

    return err;
}


ngx_int_t
ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle)
{
    char              *red_zone, *zone;
    size_t             len;
    ngx_int_t          i;
    struct sigaction   sa;

    max_threads = n + 1;

    for (i = 0; i < n; i++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        if (sigaction(NGX_CV_SIGNAL, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(%d, SIG_IGN) failed", NGX_CV_SIGNAL);
            return NGX_ERROR;
        }
    }

    len = sizeof(ngx_freebsd_kern_usrstack);
    if (sysctlbyname("kern.usrstack", &ngx_freebsd_kern_usrstack, &len,
                                                                NULL, 0) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sysctlbyname(kern.usrstack) failed");
        return NGX_ERROR;
    }

    /* the main thread stack red zone */
    rz_size = ngx_pagesize;
    red_zone = ngx_freebsd_kern_usrstack - (size + rz_size);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "usrstack: %p red zone: %p",
                   ngx_freebsd_kern_usrstack, red_zone);

    zone = mmap(red_zone, rz_size, PROT_NONE, MAP_ANON, -1, 0);
    if (zone == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "mmap(%p:%uz, PROT_NONE, MAP_ANON) red zone failed",
                      red_zone, rz_size);
        return NGX_ERROR;
    }

    if (zone != red_zone) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "red zone %p address was changed to %p", red_zone, zone);
        return NGX_ERROR;
    }

    /* create the thread errno' array */

    errnos = ngx_calloc(n * sizeof(int), cycle->log);
    if (errnos == NULL) {
        return NGX_ERROR;
    }

    /* create the thread tids array */

    tids = ngx_calloc((n + 1) * sizeof(ngx_tid_t), cycle->log);
    if (tids == NULL) {
        return NGX_ERROR;
    }

    tids[0] = ngx_pid;

    /* create the thread tls' array */

    ngx_tls = ngx_calloc(NGX_THREAD_KEYS_MAX * (n + 1) * sizeof(void *),
                         cycle->log);
    if (ngx_tls == NULL) {
        return NGX_ERROR;
    }

    nthreads = 1;

    last_stack = zone + rz_size;
    usable_stack_size = size;
    ngx_thread_stack_size = size + rz_size;

    /* allow the spinlock in libc malloc() */
    __isthreaded = 1;

    ngx_threaded = 1;

    return NGX_OK;
}


ngx_tid_t
ngx_thread_self(void)
{
    ngx_int_t  tid;

    tid = ngx_gettid();

    if (tids == NULL) {
        return ngx_pid;
    }

    return tids[tid];
}


ngx_err_t
ngx_thread_key_create(ngx_tls_key_t *key)
{
    if (nkeys >= NGX_THREAD_KEYS_MAX) {
        return NGX_ENOMEM;
    }

    *key = nkeys++;

    return 0;
}


ngx_err_t
ngx_thread_set_tls(ngx_tls_key_t key, void *value)
{
    if (key >= NGX_THREAD_KEYS_MAX) {
        return NGX_EINVAL;
    }

    ngx_tls[key * NGX_THREAD_KEYS_MAX + ngx_gettid()] = value;
    return 0;
}


ngx_mutex_t *
ngx_mutex_init(ngx_log_t *log, ngx_uint_t flags)
{
    ngx_mutex_t  *m;
    union semun   op;

    m = ngx_alloc(sizeof(ngx_mutex_t), log);
    if (m == NULL) {
        return NULL;
    }

    m->lock = 0;
    m->log = log;

    if (flags & NGX_MUTEX_LIGHT) {
        m->semid = -1;
        return m;
    }

    m->semid = semget(IPC_PRIVATE, 1, SEM_R|SEM_A);
    if (m->semid == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "semget() failed");
        return NULL;
    }

    op.val = 0;

    if (semctl(m->semid, 0, SETVAL, op) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "semctl(SETVAL) failed");

        if (semctl(m->semid, 0, IPC_RMID) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "semctl(IPC_RMID) failed");
        }

        return NULL;
    }

    return m;
}


void
ngx_mutex_destroy(ngx_mutex_t *m)
{
    if (semctl(m->semid, 0, IPC_RMID) == -1) {
        ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                      "semctl(IPC_RMID) failed");
    }

    ngx_free((void *) m);
}


ngx_int_t
ngx_mutex_dolock(ngx_mutex_t *m, ngx_int_t try)
{
    uint32_t       lock, old;
    ngx_uint_t     tries;
    struct sembuf  op;

    if (!ngx_threaded) {
        return NGX_OK;
    }

#if (NGX_DEBUG)
    if (try) {
        ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                       "try lock mutex %p lock:%XD", m, m->lock);
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                       "lock mutex %p lock:%XD", m, m->lock);
    }
#endif

    old = m->lock;
    tries = 0;

    for ( ;; ) {
        if (old & NGX_MUTEX_LOCK_BUSY) {

            if (try) {
                return NGX_AGAIN;
            }

            if (ngx_ncpu > 1 && tries++ < 1000) {

                /* the spinlock is used only on the SMP system */

                old = m->lock;
                continue;
            }

            if (m->semid == -1) {
                sched_yield();

                tries = 0;
                old = m->lock;
                continue;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                           "mutex %p lock:%XD", m, m->lock);

            /*
             * The mutex is locked so we increase a number
             * of the threads that are waiting on the mutex
             */

            lock = old + 1;

            if ((lock & ~NGX_MUTEX_LOCK_BUSY) > nthreads) {
                ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                              "%D threads wait for mutex %p, "
                              "while only %ui threads are available",
                              lock & ~NGX_MUTEX_LOCK_BUSY, m, nthreads);
                ngx_abort();
            }

            if (ngx_atomic_cmp_set(&m->lock, old, lock)) {

                ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                               "wait mutex %p lock:%XD", m, m->lock);

                /*
                 * The number of the waiting threads has been increased
                 * and we would wait on the SysV semaphore.
                 * A semaphore should wake up us more efficiently than
                 * a simple sched_yield() or usleep().
                 */

                op.sem_num = 0;
                op.sem_op = -1;
                op.sem_flg = 0;

                if (semop(m->semid, &op, 1) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                                 "semop() failed while waiting on mutex %p", m);
                    ngx_abort();
                }

                ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                               "mutex waked up %p lock:%XD", m, m->lock);

                tries = 0;
                old = m->lock;
                continue;
            }

            old = m->lock;

        } else {
            lock = old | NGX_MUTEX_LOCK_BUSY;

            if (ngx_atomic_cmp_set(&m->lock, old, lock)) {

                /* we locked the mutex */

                break;
            }

            old = m->lock;
        }

        if (tries++ > 1000) {

            ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                           "mutex %p is contested", m);

            /* the mutex is probably contested so we are giving up now */

            sched_yield();

            tries = 0;
            old = m->lock;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                   "mutex %p is locked, lock:%XD", m, m->lock);

    return NGX_OK;
}


void
ngx_mutex_unlock(ngx_mutex_t *m)
{
    uint32_t       lock, old;
    struct sembuf  op;

    if (!ngx_threaded) {
        return;
    }

    old = m->lock;

    if (!(old & NGX_MUTEX_LOCK_BUSY)) {
        ngx_log_error(NGX_LOG_ALERT, m->log, 0,
                      "trying to unlock the free mutex %p", m);
        ngx_abort();
    }

    /* free the mutex */

#if 0
    ngx_log_debug2(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                   "unlock mutex %p lock:%XD", m, old);
#endif

    for ( ;; ) {
        lock = old & ~NGX_MUTEX_LOCK_BUSY;

        if (ngx_atomic_cmp_set(&m->lock, old, lock)) {
            break;
        }

        old = m->lock;
    }

    if (m->semid == -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                       "mutex %p is unlocked", m);

        return;
    }

    /* check whether we need to wake up a waiting thread */

    old = m->lock;

    for ( ;; ) {
        if (old & NGX_MUTEX_LOCK_BUSY) {

            /* the mutex is just locked by another thread */

            break;
        }

        if (old == 0) {
            break;
        }

        /* there are the waiting threads */

        lock = old - 1;

        if (ngx_atomic_cmp_set(&m->lock, old, lock)) {

            /* wake up the thread that waits on semaphore */

            ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                           "wake up mutex %p", m);

            op.sem_num = 0;
            op.sem_op = 1;
            op.sem_flg = 0;

            if (semop(m->semid, &op, 1) == -1) {
                ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                              "semop() failed while waking up on mutex %p", m);
                ngx_abort();
            }

            break;
        }

        old = m->lock;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0,
                   "mutex %p is unlocked", m);

    return;
}


ngx_cond_t *
ngx_cond_init(ngx_log_t *log)
{
    ngx_cond_t  *cv;

    cv = ngx_alloc(sizeof(ngx_cond_t), log);
    if (cv == NULL) {
        return NULL;
    }

    cv->signo = NGX_CV_SIGNAL;
    cv->tid = -1;
    cv->log = log;
    cv->kq = -1;

    return cv;
}


void
ngx_cond_destroy(ngx_cond_t *cv)
{
    if (close(cv->kq) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, ngx_errno,
                      "kqueue close() failed");
    }

    ngx_free(cv);
}


ngx_int_t
ngx_cond_wait(ngx_cond_t *cv, ngx_mutex_t *m)
{
    int              n;
    ngx_err_t        err;
    struct kevent    kev;
    struct timespec  ts;

    if (cv->kq == -1) {

        /*
         * We have to add the EVFILT_SIGNAL filter in the rfork()ed thread.
         * Otherwise the thread would not get a signal event.
         *
         * However, we have not to open the kqueue in the thread,
         * it is simply handy do it together.
         */

        cv->kq = kqueue();
        if (cv->kq == -1) {
            ngx_log_error(NGX_LOG_ALERT, cv->log, ngx_errno, "kqueue() failed");
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cv->log, 0,
                       "cv kq:%d signo:%d", cv->kq, cv->signo);

        kev.ident = cv->signo;
        kev.filter = EVFILT_SIGNAL;
        kev.flags = EV_ADD;
        kev.fflags = 0;
        kev.data = 0;
        kev.udata = NULL;

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(cv->kq, &kev, 1, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cv->log, ngx_errno, "kevent() failed");
            return NGX_ERROR;
        }

        cv->tid = ngx_thread_self();
    }

    ngx_mutex_unlock(m);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cv->log, 0,
                   "cv %p wait, kq:%d, signo:%d", cv, cv->kq, cv->signo);

    for ( ;; ) {
        n = kevent(cv->kq, NULL, 0, &kev, 1, NULL);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cv->log, 0,
                       "cv %p kevent: %d", cv, n);

        if (n == -1) {
            err = ngx_errno;
            ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                          cv->log, ngx_errno,
                          "kevent() failed while waiting condition variable %p",
                          cv);

            if (err == NGX_EINTR) {
                break;
            }

            return NGX_ERROR;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ALERT, cv->log, 0,
                          "kevent() returned no events "
                          "while waiting condition variable %p",
                          cv);
            continue;
        }

        if (kev.filter != EVFILT_SIGNAL) {
            ngx_log_error(NGX_LOG_ALERT, cv->log, 0,
                          "kevent() returned unexpected events: %d "
                          "while waiting condition variable %p",
                          kev.filter, cv);
            continue;
        }

        if (kev.ident != (uintptr_t) cv->signo) {
            ngx_log_error(NGX_LOG_ALERT, cv->log, 0,
                          "kevent() returned unexpected signal: %d ",
                          "while waiting condition variable %p",
                          kev.ident, cv);
            continue;
        }

        break;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p is waked up", cv);

    ngx_mutex_lock(m);

    return NGX_OK;
}


ngx_int_t
ngx_cond_signal(ngx_cond_t *cv)
{
    ngx_err_t  err;

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cv->log, 0,
                   "cv %p to signal %P %d",
                   cv, cv->tid, cv->signo);

    if (cv->tid == -1) {
        return NGX_OK;
    }

    if (kill(cv->tid, cv->signo) == -1) {

        err = ngx_errno;

        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                     "kill() failed while signaling condition variable %p", cv);

        if (err == NGX_ESRCH) {
            cv->tid = -1;
        }

        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p is signaled", cv);

    return NGX_OK;
}
