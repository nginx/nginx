
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if ( __i386__ || __amd64__ )

#define NGX_HAVE_ATOMIC_OPS  1

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


#if 0

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

#endif


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

#define NGX_HAVE_ATOMIC_OPS  1

typedef volatile uint32_t  ngx_atomic_t;


static ngx_inline uint32_t ngx_atomic_inc(ngx_atomic_t *value)
{
    uint32_t  old, new, res;

    old = *value;

    for ( ;; ) {

        new = old + 1;
        res = new;

        __asm__ volatile (

        "casa [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old));

        if (res == old) {
            return new;
        }

        old = res;
    }
}


static ngx_inline uint32_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
                                              ngx_atomic_t old,
                                              ngx_atomic_t set)
{
    uint32_t  res = (uint32_t) set;

    __asm__ volatile (

    "casa [%1] 0x80, %2, %0"

    : "+r" (res) : "r" (lock), "r" (old));

    return (res == old);
}

#else

#define NGX_HAVE_ATOMIC_OPS  0

typedef volatile uint32_t  ngx_atomic_t;

#define ngx_atomic_inc(x)  ++(*(x));

static ngx_inline uint32_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
                                              ngx_atomic_t old,
                                              ngx_atomic_t set)
{
     return 1;
}

#endif


void ngx_spinlock(ngx_atomic_t *lock, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
