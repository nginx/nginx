
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_page_size - 1), i.e. 4095 on x86.
 * On FreeBSD 5.x it allows to use the zero copy sending.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE   (16 * 1024)

#define ngx_test_null(p, alloc, rc)  if ((p = alloc) == NULL) { return rc; }


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t  *next;
    void              *alloc;
};


struct ngx_pool_s {
    char              *last;
    char              *end;
    ngx_pool_t        *next;
    ngx_pool_large_t  *large;
    ngx_log_t         *log;
};


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
