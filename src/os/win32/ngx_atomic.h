
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HAVE_ATOMIC_OPS   1

typedef uint32_t  ngx_atomic_int_t;
typedef volatile ngx_atomic_int_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN  sizeof("-2147483648") - 1


#define ngx_atomic_inc(p)       InterlockedIncrement((long *) p)
#define ngx_atomic_dec(p)       InterlockedDecrement((long *) p)


#if defined( __WATCOMC__ ) || defined( __BORLANDC__ ) || ( _MSC_VER >= 1300 )

/* the new SDK headers */

#define ngx_atomic_cmp_set(lock, old, set)                                    \
     (InterlockedCompareExchange((long *) lock, set, old) == old)

#else

/* the old MS VC6.0SP2 SDK headers */

#define ngx_atomic_cmp_set(lock, old, set)                                    \
     (InterlockedCompareExchange((void **) lock, (void *) set, (void *) old)  \
      == (void *) old)

#endif


void ngx_spinlock(ngx_atomic_t *lock, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
