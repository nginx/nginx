
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name)
{
    mtx->lock = addr;

    if (mtx->spin == (ngx_uint_t) -1) {
        return NGX_OK;
    }

    mtx->spin = 2048;

#if (NGX_HAVE_POSIX_SEM)

    if (sem_init(&mtx->sem, 1, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_init() failed");
    } else {
        mtx->semaphore = 1;
    }

#endif

    return NGX_OK;
}


void
ngx_shmtx_destory(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_atomic_uint_t  val;

    val = *mtx->lock;

    return ((val & 0x80000000) == 0
            && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000));
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;
    ngx_atomic_uint_t  val;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

        val = *mtx->lock;

        if ((val & 0x80000000) == 0
            && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000))
        {
            return;
        }

        if (ngx_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }

                val = *mtx->lock;

                if ((val & 0x80000000) == 0
                    && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000))
                {
                    return;
                }
            }
        }

#if (NGX_HAVE_POSIX_SEM)

        if (mtx->semaphore) {
            val = *mtx->lock;

            if ((val & 0x80000000)
                && ngx_atomic_cmp_set(mtx->lock, val, val + 1))
            {
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                               "shmtx wait %XA", val);

                while (sem_wait(&mtx->sem) == -1) {
                    ngx_err_t  err;

                    err = ngx_errno;

                    if (err != NGX_EINTR) {
                        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                                   "sem_wait() failed while waiting on shmtx");
                        break;
                    }
                }

                ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                               "shmtx awoke");
            }

            continue;
        }

#endif

        ngx_sched_yield();
    }
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_atomic_uint_t  val, old, wait;

    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

    for ( ;; ) {

        old = *mtx->lock;
        wait = old & 0x7fffffff;
        val = wait ? wait - 1 : 0;

        if (ngx_atomic_cmp_set(mtx->lock, old, val)) {
            break;
        }
    }

#if (NGX_HAVE_POSIX_SEM)

    if (wait == 0 || !mtx->semaphore) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx wake %XA", old);

    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name)
{
    if (mtx->name) {

        if (ngx_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NGX_OK;
        }

        ngx_shmtx_destory(mtx);
    }

    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}


void
ngx_shmtx_destory(ngx_shmtx_t *mtx)
{
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NGX_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCESS) {
        return 0;
    }

#endif

    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}

#endif
