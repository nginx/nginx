
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ALLOC_H_INCLUDED_
#define _NGX_ALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

#define ngx_free          free


/*
 * Linux has memalign() or posix_memalign()
 * Solaris has memalign()
 * FreeBSD has not memalign() or posix_memalign() but its malloc() alignes
 * allocations bigger than page size at the page boundary.
 */

#if (HAVE_POSIX_MEMALIGN || HAVE_MEMALIGN)

void *ngx_memalign(size_t alignment, size_t size, ngx_log_t *log);

#else

#define ngx_memalign(alignment, size, log)  ngx_alloc(size, log)

#endif


extern int ngx_pagesize;


#endif /* _NGX_ALLOC_H_INCLUDED_ */
