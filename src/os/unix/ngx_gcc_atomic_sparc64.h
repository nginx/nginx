
/*
 * Copyright (C) Igor Sysoev
 */


/*
 * "casa   [r1] 0x80, r2, r0"  and
 * "casxa  [r1] 0x80, r2, r0"  do the following:
 *
 *     if ([r1] == r2) {
 *         swap(r0, [r1]);
 *     } else {
 *         r0 = [r1];
 *     }
 *
 * so "r0 == r2" means that the operation was successfull.
 *
 *
 * The "r" means the general register.
 * The "+r" means the general register used for both input and output.
 */


#if (NGX_PTR_SIZE == 4)
#define NGX_CASA  "casa"
#else
#define NGX_CASA  "casxa"
#endif


static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    __asm__ volatile (

    NGX_CASA " [%1] 0x80, %2, %0"

    : "+r" (set) : "r" (lock), "r" (old) : "memory");

    return (set == old);
}


static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    ngx_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        __asm__ volatile (

        NGX_CASA " [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old) : "memory");

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#if (NGX_SMP)
#define ngx_memory_barrier()                                                  \
            __asm__ volatile (                                                \
            "membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad"        \
            ::: "memory")
#else
#define ngx_memory_barrier()   __asm__ volatile ("" ::: "memory")
#endif

#define ngx_cpu_pause()
