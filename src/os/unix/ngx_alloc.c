
/*
 * Copyright (C) Igor Sysoev
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
                      "malloc() %uz bytes failed", size);
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

    if (posix_memalign(&p, alignment, size) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "posix_memalign() %uz bytes aligned to %uz failed",
                      size, alignment);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz", p, size);

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
                      "memalign() %uz bytes aligned to %uz failed",
                      size, alignment);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz", p, size);

    return p;
}

#endif
