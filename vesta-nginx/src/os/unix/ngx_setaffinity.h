
/*
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_SETAFFINITY_H_INCLUDED_
#define _NGX_SETAFFINITY_H_INCLUDED_


#if (NGX_HAVE_SCHED_SETAFFINITY || NGX_HAVE_CPUSET_SETAFFINITY)

#define NGX_HAVE_CPU_AFFINITY 1

void ngx_setaffinity(uint64_t cpu_affinity, ngx_log_t *log);

#else

#define ngx_setaffinity(cpu_affinity, log)

#endif


#endif /* _NGX_SETAFFINITY_H_INCLUDED_ */
