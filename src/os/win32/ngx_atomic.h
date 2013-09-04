
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HAVE_ATOMIC_OPS   1

typedef int32_t                     ngx_atomic_int_t;
typedef uint32_t                    ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


#if defined( __WATCOMC__ ) || defined( __BORLANDC__ ) || defined(__GNUC__)    \
    || ( _MSC_VER >= 1300 )

/* the new SDK headers */

#define ngx_atomic_cmp_set(lock, old, set)                                    \
     ((ngx_atomic_uint_t) InterlockedCompareExchange((long *) lock, set, old) \
                          == old)

#else

/* the old MS VC6.0SP2 SDK headers */

#define ngx_atomic_cmp_set(lock, old, set)                                    \
     (InterlockedCompareExchange((void **) lock, (void *) set, (void *) old)  \
      == (void *) old)

#endif


#define ngx_atomic_fetch_add(p, add) InterlockedExchangeAdd((long *) p, add)


#define ngx_memory_barrier()


#if defined( __BORLANDC__ ) || ( __WATCOMC__ < 1230 )

/*
 * Borland C++ 5.5 (tasm32) and Open Watcom C prior to 1.3
 * do not understand the "pause" instruction
 */

#define ngx_cpu_pause()
#else
#define ngx_cpu_pause()       __asm { pause }
#endif


void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
