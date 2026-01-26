
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_uint_t  ngx_pagesize;
ngx_uint_t  ngx_pagesize_shift;
ngx_uint_t  ngx_cacheline_size;


void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    void  *p;

    p = malloc(size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "malloc(%uz) failed", size);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}


void *
ngx_calloc(size_t size, ngx_log_t *log)
{
    void  *p;

    p = ngx_alloc(size, log);

    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


#if (NGX_HAVE_POSIX_MEMALIGN)

void *
ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    void  *p;
    int    err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        ngx_log_error(NGX_LOG_EMERG, log, err,
                      "posix_memalign(%uz, %uz) failed", alignment, size);
        p = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#elif (NGX_HAVE_MEMALIGN)

void *
ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "memalign(%uz, %uz) failed", alignment, size);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#endif


void *
ngx_kalloc(ngx_uint_t npages, ngx_log_t *log)
{
    void    *p;
    size_t   size;

    size = npages * ngx_pagesize;

    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "mmap(MAP_ANON, %uz) failed", size);
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "mmap: %p:%uz", p, size);

    return p;
}


ngx_int_t
ngx_kfree(void *p, ngx_uint_t npages, ngx_log_t *log)
{
    size_t  size;

    size = npages * ngx_pagesize;

    if (munmap(p, size) == -1) {
        if (log) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "munmap(%p, %uz) failed", p, size);
        }

        return NGX_ERROR;
    }

    if (log) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "munmap: %p:%uz", p, size);
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmemlock(void *p, ngx_uint_t npages, ngx_log_t *log)
{
    size_t  size;

    size = npages * ngx_pagesize;

    if (mprotect(p, size, PROT_READ) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "mprotect(%p, %uz) failed", p, size);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "mprotect: %p:%uz", p, size);

    return NGX_OK;
}


ngx_int_t
ngx_kmemunlock(void *p, ngx_uint_t npages, ngx_log_t *log)
{
    size_t  size;

    size = npages * ngx_pagesize;

    if (mprotect(p, size, PROT_READ|PROT_WRITE) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "mprotect(%p, %uz) failed", p, size);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "mprotect: %p:%uz", p, size);

    return NGX_OK;
}
