
/*
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_SETAFFINITY_H_INCLUDED_
#define _NGX_SETAFFINITY_H_INCLUDED_


#if (NGX_HAVE_SCHED_SETAFFINITY || NGX_HAVE_CPUSET_SETAFFINITY)

#define NGX_HAVE_CPU_AFFINITY 1

#if (NGX_HAVE_SCHED_SETAFFINITY)

typedef cpu_set_t  ngx_cpuset_t;

#elif (NGX_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

typedef cpuset_t  ngx_cpuset_t;

#endif

void ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log);
ngx_int_t ngx_get_cpu_allowed(ngx_cpuset_t *mask, ngx_log_t *log);
ngx_int_t ngx_get_cpu_inherited(void);


extern ngx_cpuset_t  ngx_cpu_allowed;
extern ngx_int_t     ngx_ncpu_inherited;

#else

#define ngx_setaffinity(cpu_affinity, log)

typedef uint64_t  ngx_cpuset_t;

#endif


#endif /* _NGX_SETAFFINITY_H_INCLUDED_ */
