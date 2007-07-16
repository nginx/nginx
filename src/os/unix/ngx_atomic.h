
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_DARWIN_ATOMIC)

/*
 * use Darwin 8 atomic(3) and barrier(3) operations
 * optimized at run-time for UP and SMP
 */

#include <libkern/OSAtomic.h>

/* "bool" conflicts with perl's CORE/handy.h
 * "true" and "false" conflict with nginx, and of course we can rename them,
 * but we need to undef "bool" anyway
 */
#undef bool
#undef true
#undef false


#define NGX_HAVE_ATOMIC_OPS  1

#if (NGX_PTR_SIZE == 8)

typedef int64_t                     ngx_atomic_int_t;
typedef uint64_t                    ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN            sizeof("-9223372036854775808") - 1

#define ngx_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap64Barrier(old, new, (int64_t *) lock)

#define ngx_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd64(add, (int64_t *) value) - add)

#else

typedef int32_t                     ngx_atomic_int_t;
typedef uint32_t                    ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN            sizeof("-2147483648") - 1

#define ngx_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap32Barrier(old, new, (int32_t *) lock)

#define ngx_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd32(add, (int32_t *) value) - add)

#endif

#define ngx_memory_barrier()        OSMemoryBarrier()

#define ngx_cpu_pause()

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


#else /* !(NGX_DARWIN) */


#if ( __i386__ || __i386 )

typedef int32_t                     ngx_atomic_int_t;
typedef uint32_t                    ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN            sizeof("-2147483648") - 1


#if ( __SUNPRO_C )

#define NGX_HAVE_ATOMIC_OPS  1

ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set);

ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so ngx_cpu_pause is declared in src/os/unix/ngx_sunpro_x86.il
 */

void
ngx_cpu_pause(void);

/* the code in src/os/unix/ngx_sunpro_x86.il */

#define ngx_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define NGX_HAVE_ATOMIC_OPS  1

#include "ngx_gcc_atomic_x86.h"

#endif


#elif ( __amd64__ || __amd64 )

typedef int64_t                     ngx_atomic_int_t;
typedef uint64_t                    ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN            sizeof("-9223372036854775808") - 1


#if ( __SUNPRO_C )

#define NGX_HAVE_ATOMIC_OPS  1

ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set);

ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so ngx_cpu_pause is declared in src/os/unix/ngx_sunpro_amd64.il
 */

void
ngx_cpu_pause(void);

/* the code in src/os/unix/ngx_sunpro_amd64.il */

#define ngx_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define NGX_HAVE_ATOMIC_OPS  1

#include "ngx_gcc_atomic_amd64.h"

#endif


#elif ( __sparc__ || __sparc || __sparcv9 )

#if (NGX_PTR_SIZE == 8)

typedef int64_t                     ngx_atomic_int_t;
typedef uint64_t                    ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN            sizeof("-9223372036854775808") - 1

#else

typedef int32_t                     ngx_atomic_int_t;
typedef uint32_t                    ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN            sizeof("-2147483648") - 1

#endif

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


#if ( __SUNPRO_C )

#define NGX_HAVE_ATOMIC_OPS  1

#include "ngx_sunpro_atomic_sparc64.h"


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define NGX_HAVE_ATOMIC_OPS  1

#include "ngx_gcc_atomic_sparc64.h"

#endif


#elif ( __powerpc__ || __POWERPC__ )

#define NGX_HAVE_ATOMIC_OPS  1

#if (NGX_PTR_SIZE == 8)

typedef int64_t                     ngx_atomic_int_t;
typedef uint64_t                    ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN            sizeof("-9223372036854775808") - 1

#else

typedef int32_t                     ngx_atomic_int_t;
typedef uint32_t                    ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN            sizeof("-2147483648") - 1

#endif

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


#include "ngx_gcc_atomic_ppc.h"


#endif

#endif


#if !(NGX_HAVE_ATOMIC_OPS)

#define NGX_HAVE_ATOMIC_OPS  0

typedef int32_t                     ngx_atomic_int_t;
typedef uint32_t                    ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN            sizeof("-2147483648") - 1


static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
     ngx_atomic_uint_t set)
{
     if (*lock == old) {
         *lock = set;
         return 1;
     }

     return 0;
}


static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
     ngx_atomic_int_t  old;

     old = *value;
     *value += add;

     return old;
}

#define ngx_memory_barrier()
#define ngx_cpu_pause()

#endif


void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
