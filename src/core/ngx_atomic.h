#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if ( __i386__ || __amd64__ )

typedef volatile uint32_t  ngx_atomic_t;

#if (NGX_SMP)
#define NGX_SMP_LOCK  "lock;"
#else
#define NGX_SMP_LOCK
#endif


static ngx_inline uint32_t ngx_atomic_inc(ngx_atomic_t *value)
{
    uint32_t  old;

    __asm__ volatile (

        NGX_SMP_LOCK
    "   xaddl  %0, %2;   "
    "   incl   %0;       "

    : "=q" (old) : "0" (1), "m" (*value));

    return old;
}


static ngx_inline uint32_t ngx_atomic_dec(ngx_atomic_t *value)
{
    uint32_t  old;

    __asm__ volatile (

        NGX_SMP_LOCK
    "   xaddl  %0, %1;   "
    "   decl   %0;       "

    : "=q" (old) : "0" (-1), "m" (*value));

    return old;
}


static ngx_inline uint32_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
                                              ngx_atomic_t old,
                                              ngx_atomic_t set)
{
    uint32_t  res;

    __asm__ volatile (

        NGX_SMP_LOCK
    "   cmpxchgl  %3, %1;   "
    "   setz      %%al;     "
    "   movzbl    %%al, %0; "

    : "=a" (res) : "m" (*lock), "a" (old), "q" (set));

    return res;
}


#elif (WIN32)

#define ngx_atomic_inc(p)       InterlockedIncrement((long *) p)
#define ngx_atomic_dec(p)       InterlockedDecrement((long *) p)
/* STUB */
#define ngx_atomic_cmp_set(lock, old, set)   1
#if 0
#define ngx_atomic_cmp_set(lock, old, set)                                   \
                                  InterlockedCompareExchange(lock, set, old)
#endif


#else

typedef volatile uint32_t  ngx_atomic_t;

/* STUB */
#define ngx_atomic_inc(x)   (*(x))++;
#define ngx_atomic_dec(x)   (*(x))--;
#define ngx_atomic_cmp_set(lock, old, set)   1
/**/

#endif


static ngx_inline ngx_int_t ngx_trylock(ngx_atomic_t *lock)
{
    if (*lock) {
        return NGX_BUSY;
    }

    if (ngx_atomic_cmp_set(lock, 0, 1)) {
        return NGX_OK;
    }

    return NGX_BUSY;
}


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
