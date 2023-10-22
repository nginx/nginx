
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>


#if (NGX_LINUX)

/*
 * Linux thread id is a pid of thread created by clone(2),
 * glibc does not provide a wrapper for gettid().
 */

ngx_tid_t
ngx_thread_tid(void)
{
    return syscall(SYS_gettid);
}

#elif (NGX_FREEBSD) && (__FreeBSD_version >= 900031)

#include <pthread_np.h>

ngx_tid_t
ngx_thread_tid(void)
{
    return pthread_getthreadid_np();
}

#elif (NGX_DARWIN)

/*
 * MacOSX thread has two thread ids:
 *
 * 1) MacOSX 10.6 (Snow Leoprad) has pthread_threadid_np() returning
 *    an uint64_t value, which is obtained using the __thread_selfid()
 *    syscall.  It is a number above 300,000.
 */

ngx_tid_t
ngx_thread_tid(void)
{
    uint64_t  tid;

    (void) pthread_threadid_np(NULL, &tid);
    return tid;
}

/*
 * 2) Kernel thread mach_port_t returned by pthread_mach_thread_np().
 *    It is a number in range 100-100,000.
 *
 * return pthread_mach_thread_np(pthread_self());
 */

#else

ngx_tid_t
ngx_thread_tid(void)
{
    return (uint64_t) (uintptr_t) pthread_self();
}

#endif
