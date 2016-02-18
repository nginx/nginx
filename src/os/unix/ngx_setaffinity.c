
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


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

#endif
