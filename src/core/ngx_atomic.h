#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifdef __i386__

typedef uint32_t  ngx_atomic_t;

#if (NGX_SMP)
#define NGX_SMP_LOCK  "lock"
#else
#define NGX_SMP_LOCK
#endif


static ngx_inline uint32_t ngx_atomic_inc(ngx_atomic_t *value)
{
    uint32_t  old;

    __asm__ __volatile ("

        movl   $1, %0
    "   NGX_SMP_LOCK
    "   xaddl  %0, %1

    ": "=a" (old) : "m" (*value));

    return old;
}


static ngx_inline uint32_t ngx_atomic_dec(ngx_atomic_t *value)
{
    uint32_t  old;

    __asm__ __volatile ("

        movl   $-1, %0
    "   NGX_SMP_LOCK
    "   xaddl  %0, %1

    ": "=a" (old) : "m" (*value));

    return old;
}


static ngx_inline uint32_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
                                              ngx_atomic_t old,
                                              ngx_atomic_t set)
{
    uint32_t  res;

    __asm__ __volatile ("

    "   NGX_SMP_LOCK
    "   cmpxchgl  %3, %1
        setzb     %%al
        movzbl    %%al, %0

    ": "=a" (res) : "m" (*lock), "a" (old), "q" (set));

    return res;
}

#else

typedef uint32_t  ngx_atomic_t;

/* STUB */
#define ngx_atomic_inc(x)   x++;
#define ngx_atomic_dec(x)   x--;
#define ngx_atomic_cmp_set(lock, old, set)   1;
/**/

#endif


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
