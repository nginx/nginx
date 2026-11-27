
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_CPU_AFFINITY)

ngx_cpuset_t  ngx_cpu_allowed;
ngx_int_t     ngx_ncpu_inherited;

#endif


#if (NGX_HAVE_CPUSET_SETAFFINITY)

void
ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log)
{
    ngx_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "cpuset_setaffinity(): using cpu #%ui", i);
        }
    }

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), cpu_affinity) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "cpuset_setaffinity() failed");
    }
}


/*
 * The CPUs we may run on are those of the cpuset the process is assigned
 * to, not its current mask, which "worker_cpu_affinity" can widen.
 *
 * Returns the number of CPUs in the mask, or 0 if unknown.
 */

ngx_int_t
ngx_get_cpu_allowed(ngx_cpuset_t *mask, ngx_log_t *log)
{
#if (NGX_HAVE_CPUSET_GETAFFINITY && NGX_HAVE_CPU_COUNT)

    if (cpuset_getaffinity(CPU_LEVEL_CPUSET, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), mask)
        == -1)
    {
        return 0;
    }

    return CPU_COUNT(mask);

#else

    return 0;

#endif
}


/*
 * The number of CPUs in the process's own mask, which may be narrower
 * than its cpuset, e.g. as set by "cpuset -l".
 */

ngx_int_t
ngx_get_cpu_inherited(void)
{
#if (NGX_HAVE_CPUSET_GETAFFINITY && NGX_HAVE_CPU_COUNT)
    cpuset_t  mask;

    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), &mask)
        == -1)
    {
        return 0;
    }

    return CPU_COUNT(&mask);

#else

    return 0;

#endif
}

#elif (NGX_HAVE_SCHED_SETAFFINITY)

void
ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log)
{
    ngx_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "sched_setaffinity(): using cpu #%ui", i);
        }
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sched_setaffinity() failed");
    }
}


/*
 * The current mask may have been inherited (e.g. from taskset(1)) and can
 * be widened by "worker_cpu_affinity", so it is not the limit.  A cpuset
 * is, so temporarily ask for all CPUs and see what the kernel leaves us,
 * then restore the original mask.
 *
 * Returns the number of CPUs in the mask, or 0 if unknown.
 */

ngx_int_t
ngx_get_cpu_allowed(ngx_cpuset_t *mask, ngx_log_t *log)
{
#if (NGX_HAVE_SCHED_GETAFFINITY && NGX_HAVE_CPU_COUNT)
    cpu_set_t  orig;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &orig) == -1) {
        return 0;
    }

    ngx_memset(mask, 0xff, sizeof(cpu_set_t));

    if (sched_setaffinity(0, sizeof(cpu_set_t), mask) == -1) {
        /* the mask cannot be changed, so the inherited one is the limit */
        *mask = orig;
        return CPU_COUNT(mask);
    }

    if (sched_getaffinity(0, sizeof(cpu_set_t), mask) == -1) {
        *mask = orig;
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), &orig) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sched_setaffinity() failed to restore cpu mask");
    }

    return CPU_COUNT(mask);

#else

    return 0;

#endif
}


/*
 * The number of CPUs in the inherited mask, e.g. as set by taskset(1).
 */

ngx_int_t
ngx_get_cpu_inherited(void)
{
#if (NGX_HAVE_SCHED_GETAFFINITY && NGX_HAVE_CPU_COUNT)
    cpu_set_t  mask;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        return 0;
    }

    return CPU_COUNT(&mask);

#else

    return 0;

#endif
}

#endif
