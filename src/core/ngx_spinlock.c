
#include <ngx_config.h>
#include <ngx_core.h>


void ngx_spinlock(ngx_atomic_t *lock, ngx_uint_t spin)
{
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
}
