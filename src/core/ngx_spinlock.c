
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


void ngx_spinlock(ngx_atomic_t *lock, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  tries;

    tries = 0;

    for ( ;; ) {

        if (*lock) {
            if (ngx_ncpu > 1 && tries++ < spin) {
                continue;
            }

            ngx_sched_yield();

            tries = 0;

        } else {
            if (ngx_atomic_cmp_set(lock, 0, 1)) {
                return;
            }
        }
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
