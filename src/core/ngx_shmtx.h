
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;
#else
    ngx_fd_t       fd;
    u_char        *name;
#endif
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name);


#if (NGX_HAVE_ATOMIC_OPS)

static ngx_inline ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
}

#define ngx_shmtx_lock(mtx)   ngx_spinlock((mtx)->lock, ngx_pid, 1024)

#define ngx_shmtx_unlock(mtx) (void) ngx_atomic_cmp_set((mtx)->lock, ngx_pid, 0)

#define ngx_shmtx_destory(mtx)


#else

static ngx_inline ngx_uint_t
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

    ngx_log_abort(err, ngx_trylock_fd_n " failed");

    return 0;
}


static ngx_inline void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " failed");
}


static ngx_inline void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " failed");
}


void ngx_shmtx_destory(ngx_shmtx_t *mtx);

#endif


#endif /* _NGX_SHMTX_H_INCLUDED_ */
