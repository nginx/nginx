
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
#define ngx_memalign(alignment, size, log)  ngx_alloc(size, log)

extern int ngx_pagesize;


#endif /* _NGX_ALLOC_H_INCLUDED_ */
