

typedef struct {
    int  lock;
} ngx_mutex_t;


static inline int ngx_spin_lock(ngx_mutex_t *m, int count)
{
    int  lock;

    __asm__ __volatile("

get_lock:
        mov   $1, %1
        xchg  %1, %2
        cmp   $0, %1
        jne   spin_lock

spin_lock:
        cmp   $0, %3
        je    failed

        dec   %3
        rep   nop
        cmp   $0, %2
        jne   spin_lock

    ": "=q" (lock), "m" (m->lock), "q" (count));
}
