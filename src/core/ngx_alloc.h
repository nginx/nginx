#ifndef _NGX_ALLOC_H_INCLUDED_
#define _NGX_ALLOC_H_INCLUDED_


#include <ngx_config.h>

#include <ngx_log.h>


#define NGX_MAX_ALLOC_FROM_POOL (8192 - sizeof(ngx_pool_t))
#define NGX_DEFAULT_POOL_SIZE   (16 * 1024)

#define ngx_test_null(p, alloc, rc)  if ((p = alloc) == NULL) { return rc; }


typedef struct ngx_pool_large_s  ngx_pool_large_t;
struct ngx_pool_large_s {
    ngx_pool_large_t  *next;
    void              *alloc;
};

typedef struct ngx_pool_s  ngx_pool_t;
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


#endif /* _NGX_ALLOC_H_INCLUDED_ */
