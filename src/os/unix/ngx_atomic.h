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


#elif ( __sparc__ )

typedef volatile uint32_t  ngx_atomic_t;


static ngx_inline uint32_t ngx_atomic_inc(ngx_atomic_t *value)
{
    uint32_t  old, new, res;

    old = *value;

    for ( ;; ) {

        new = old + 1;
        res = new;

        __asm__ volatile (

        "casa [%1]ASI_P, %2, %0"

        : "+r" (res) : "r" (value), "r" (old));

        if (res == old) {
            return new;
        }

        old = res;
    }
}


/* STUB */
#define ngx_atomic_dec(x)   (*(x))--;
/**/


static ngx_inline uint32_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
                                              ngx_atomic_t old,
                                              ngx_atomic_t set)
{
    uint32_t  res = (uint32_t) set;

    __asm__ volatile (

    "casa [%1]ASI_P, %2, %0"

    : "+r" (res) : "r" (lock), "r" (old));

    return (res == old);
}

#else

typedef volatile uint32_t  ngx_atomic_t;

/* STUB */
#define ngx_atomic_inc(x)   (*(x))++;
#define ngx_atomic_dec(x)   (*(x))--;
#define ngx_atomic_cmp_set(lock, old, set)   1
/**/

#endif


void ngx_spinlock(ngx_atomic_t *lock, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
