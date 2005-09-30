
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if ( __i386__ || __i386 )

#define NGX_HAVE_ATOMIC_OPS  1

typedef int32_t  ngx_atomic_int_t;
typedef uint32_t  ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN  sizeof("-2147483648") - 1


#if (NGX_SMP)
#define NGX_SMP_LOCK  "lock;"
#else
#define NGX_SMP_LOCK
#endif

/*
 * the "=q" is any of the %eax, %ebx, %ecx, or %edx registers.
 * the '"0" (1)' parameter preloads 1 into %0.
 * the "cc" means that flags were changed.
 *
 * "xadd  r, [m]":
 *
 *     temp = [m];
 *     [m] += r;
 *     r = temp;
 */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_inc(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  old;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddl  %0, %2;   "
    "    incl   %0;       "

    : "=q" (old) : "0" (1), "m" (*value) : "cc", "memory");

    return old;
}


static ngx_inline ngx_atomic_uint_t
ngx_atomic_dec(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  old;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddl  %0, %2;   "
    "    decl   %0;       "

    : "=q" (old) : "0" (-1), "m" (*value) : "cc", "memory");

    return old;
}


/*
 * the "q" is any of the %eax, %ebx, %ecx, or %edx registers.
 * the "=a" and "a" are the %eax register.  Although we can return result
 * in any register, we use %eax because it is used in cmpxchg anyway.
 *
 * "cmpxchg  r, [m]":
 *
 *     if (eax == [m]) {
 *         zf = 1;
 *         [m] = r;
 *     } else {
 *         zf = 0;
 *         eax = [m];
 *     }
 */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    ngx_atomic_uint_t  res;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    cmpxchgl  %3, %1;   "
    "    setz      %b0;      "
    "    movzbl    %b0, %0;  "

    : "=a" (res) : "m" (*lock), "a" (old), "q" (set) : "cc", "memory");

    return res;
}


#elif ( __amd64__ || __amd64 )

#define NGX_HAVE_ATOMIC_OPS  1

typedef int64_t  ngx_atomic_int_t;
typedef uint64_t  ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN  sizeof("-9223372036854775808") - 1


#if (NGX_SMP)
#define NGX_SMP_LOCK  "lock;"
#else
#define NGX_SMP_LOCK
#endif


static ngx_inline ngx_atomic_uint_t
ngx_atomic_inc(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  old;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddq  %0, %2;   "
    "    incq   %0;       "

    : "=r" (old) : "0" (1), "m" (*value) : "cc", "memory");

    return old;
}


/* the '"0" (-1LL)' parameter preloads -1 into the 64-bit %0 register */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_dec(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  old;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddq  %0, %2;   "
    "    decq   %0;       "

    : "=r" (old) : "0" (-1LL), "m" (*value) : "cc", "memory");

    return old;
}


/* the "=a" and "a" are the %rax register. */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    ngx_atomic_uint_t  res;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    cmpxchgq  %3, %1;   "
    "    setz      %b0;      "
    "    movzbq    %b0, %0;  "

    : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");

    return res;
}


#elif ( __sparc__ || __sparcv9 )

#define NGX_HAVE_ATOMIC_OPS  1

#if (NGX_PTR_SIZE == 8)
typedef int64_t  ngx_atomic_int_t;
typedef uint64_t  ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN  sizeof("-9223372036854775808") - 1
#define NGX_CASXA         "casxa"
#else
typedef int32_t  ngx_atomic_int_t;
typedef uint32_t  ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN  sizeof("-2147483648") - 1
#define NGX_CASXA         "casa"
#endif

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


/*
 * the "+r" means the general register used for both input and output.
 *
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
 */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_inc(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  old, new, res;

    old = *value;

    for ( ;; ) {

        new = old + 1;
        res = new;

        __asm__ volatile (

        NGX_CASXA " [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old) : "memory");

        if (res == old) {
            return new;
        }

        old = res;
    }
}


static ngx_inline ngx_atomic_uint_t
ngx_atomic_dec(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  old, new, res;

    old = *value;

    for ( ;; ) {

        new = old - 1;
        res = new;

        __asm__ volatile (

        NGX_CASXA " [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old) : "memory");

        if (res == old) {
            return new;
        }

        old = res;
    }
}


static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    __asm__ volatile (

    NGX_CASXA " [%1] 0x80, %2, %0"

    : "+r" (set) : "r" (lock), "r" (old) : "memory");

    return (set == old);
}


#elif ( __ppc__ || __powerpc__ )

#define NGX_HAVE_ATOMIC_OPS  1

#if (NGX_PTR_SIZE == 8)
typedef int64_t  ngx_atomic_int_t;
typedef uint64_t  ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN  sizeof("-9223372036854775808") - 1
#else
typedef int32_t  ngx_atomic_int_t;
typedef uint32_t  ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN  sizeof("-2147483648") - 1
#endif

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


/*
 * the ppc assembler treats ";" as comment, so we have to use "\n".
 * the minus in "bne-" is a hint for the branch prediction unit that
 * this branch is unlikely to be taken.
 *
 * the "=&r" means that no input registers can be used.
 * the "=&b" means that the base registers can be used only, i.e. any register
 * except r0.  the r0 register can not be used in "addi  r0, r0, 1".
 * the "1b" means the nearest backward label "1" and the "1f" means
 * the nearest forward label "1".
 */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_inc(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  res;

    __asm__ volatile (

    "1:  lwarx   %0, 0, %1  \n" /* load from [value] into "res"             */
                                /*   and store reservation                  */
    "    addi    %0, %0, 1  \n" /* add "1" to "res"                         */
    "    stwcx.  %0, 0, %1  \n" /* store "res" into [value] if reservation  */
                                /*    is not cleared                        */
    "    bne-    1b         \n" /* try again if reservation was cleared     */

    : "=&b" (res) : "r" (value) : "cc", "memory");

    return res;
}


static ngx_inline ngx_atomic_uint_t
ngx_atomic_dec(ngx_atomic_t *value)
{
    ngx_atomic_uint_t  res;

    __asm__ volatile (

    "1:  lwarx   %0, 0, %1  \n" /* load from [value] into "res"             */
                                /*   and store reservation                  */
    "    addi    %0, %0, -1 \n" /* sub "1" from "res"                       */
    "    stwcx.  %0, 0, %1  \n" /* store "res" into [value] if reservation  */
                                /*    is not cleared                        */
    "    bne-    1b         \n" /* try again if reservation was cleared     */

    : "=&b" (res) : "r" (value) : "cc", "memory");

    return res;
}


static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    ngx_atomic_uint_t  res, temp;

    __asm__ volatile (

    "    li      %0, 0      \n" /* preset "0" to "res"                      */
    "    lwarx   %1, 0, %2  \n" /* load from [lock] into "temp"             */
                                /*   and store reservation                  */
    "    cmpw    %1, %3     \n" /* compare "temp" and "old"                 */
    "    bne-    1f         \n" /* not equal                                */
    "    stwcx.  %4, 0, %2  \n" /* store "set" into [lock] if reservation   */
                                /*    is not cleared                        */
    "    bne-    1f         \n" /* the reservation was cleared              */
    "    li      %0, 1      \n" /* set "1" to "res"                         */
    "1:                     \n"

    : "=&r" (res), "=&r" (temp)
    : "r" (lock), "r" (old), "r" (set)
    : "cc", "memory");

    return res;
}


#else

#define NGX_HAVE_ATOMIC_OPS  0

typedef int32_t  ngx_atomic_int_t;
typedef uint32_t  ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
#define NGX_ATOMIC_T_LEN  sizeof("-2147483648") - 1

#define ngx_atomic_inc(x)  ++(*(x))
#define ngx_atomic_dec(x)  --(*(x))

static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
     ngx_atomic_uint_t set)
{
     *lock = set;
     return 1;
}

#endif


void ngx_spinlock(ngx_atomic_t *lock, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
