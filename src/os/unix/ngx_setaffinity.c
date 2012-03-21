
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

void
ngx_setaffinity(uint64_t cpu_affinity, ngx_log_t *log)
{
    cpuset_t    mask;
    ngx_uint_t  i;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "cpuset_setaffinity(0x%08Xl)", cpu_affinity);

    CPU_ZERO(&mask);
    i = 0;
    do {
        if (cpu_affinity & 1) {
            CPU_SET(i, &mask);
        }
        i++;
        cpu_affinity >>= 1;
    } while (cpu_affinity);

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), &mask) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "cpuset_setaffinity() failed");
    }
}

#elif (NGX_HAVE_SCHED_SETAFFINITY)

void
ngx_setaffinity(uint64_t cpu_affinity, ngx_log_t *log)
{
    cpu_set_t   mask;
    ngx_uint_t  i;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "sched_setaffinity(0x%08Xl)", cpu_affinity);

    CPU_ZERO(&mask);
    i = 0;
    do {
        if (cpu_affinity & 1) {
            CPU_SET(i, &mask);
        }
        i++;
        cpu_affinity >>= 1;
    } while (cpu_affinity);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sched_setaffinity() failed");
    }
}

#endif
