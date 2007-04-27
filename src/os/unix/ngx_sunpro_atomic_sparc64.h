
/*
 * Copyright (C) Igor Sysoev
 */


#if (NGX_PTR_SIZE == 4)
#define NGX_CASA  ngx_casa
#else
#define NGX_CASA  ngx_casxa
#endif


ngx_atomic_uint_t
ngx_casa(ngx_atomic_uint_t set, ngx_atomic_uint_t old, ngx_atomic_t *lock);

ngx_atomic_uint_t
ngx_casxa(ngx_atomic_uint_t set, ngx_atomic_uint_t old, ngx_atomic_t *lock);

/* the code in src/os/unix/ngx_sunpro_sparc64.il */


static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    set = NGX_CASA(set, old, lock);

    return (set == old);
}


static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    ngx_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        res = NGX_CASA(res, old, value);

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#define ngx_memory_barrier()                                                  \
        __asm (".volatile");                                                  \
        __asm ("membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad");   \
        __asm (".nonvolatile")

#define ngx_cpu_pause()
