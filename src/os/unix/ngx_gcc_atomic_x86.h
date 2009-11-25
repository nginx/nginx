
/*
 * Copyright (C) Igor Sysoev
 */


#if (NGX_SMP)
#define NGX_SMP_LOCK  "lock;"
#else
#define NGX_SMP_LOCK
#endif


/*
 * "cmpxchgl  r, [m]":
 *
 *     if (eax == [m]) {
 *         zf = 1;
 *         [m] = r;
 *     } else {
 *         zf = 0;
 *         eax = [m];
 *     }
 *
 *
 * The "r" means the general register.
 * The "=a" and "a" are the %eax register.
 * Although we can return result in any register, we use "a" because it is
 * used in cmpxchgl anyway.  The result is actually in %al but not in %eax,
 * however, as the code is inlined gcc can test %al as well as %eax,
 * and icc adds "movzbl %al, %eax" by itself.
 *
 * The "cc" means that flags were changed.
 */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    u_char  res;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    cmpxchgl  %3, %1;   "
    "    sete      %0;       "

    : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");

    return res;
}


/*
 * "xaddl  r, [m]":
 *
 *     temp = [m];
 *     [m] += r;
 *     r = temp;
 *
 *
 * The "+r" means the general register.
 * The "cc" means that flags were changed.
 */


#if !(( __GNUC__ == 2 && __GNUC_MINOR__ <= 7 ) || ( __INTEL_COMPILER >= 800 ))

/*
 * icc 8.1 and 9.0 compile broken code with -march=pentium4 option:
 * ngx_atomic_fetch_add() always return the input "add" value,
 * so we use the gcc 2.7 version.
 *
 * icc 8.1 and 9.0 with -march=pentiumpro option or icc 7.1 compile
 * correct code.
 */

static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddl  %0, %1;   "

    : "+r" (add) : "m" (*value) : "cc", "memory");

    return add;
}


#else

/*
 * gcc 2.7 does not support "+r", so we have to use the fixed
 * %eax ("=a" and "a") and this adds two superfluous instructions in the end
 * of code, something like this: "mov %eax, %edx / mov %edx, %eax".
 */

static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    ngx_atomic_uint_t  old;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddl  %2, %1;   "

    : "=a" (old) : "m" (*value), "a" (add) : "cc", "memory");

    return old;
}

#endif


/*
 * on x86 the write operations go in a program order, so we need only
 * to disable the gcc reorder optimizations
 */

#define ngx_memory_barrier()    __asm__ volatile ("" ::: "memory")

/* old "as" does not support "pause" opcode */
#define ngx_cpu_pause()         __asm__ (".byte 0xf3, 0x90")
