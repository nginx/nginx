

void _spinlock(ngx_atomic_t *lock)
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

