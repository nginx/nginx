
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


int ngx_pagesize;


void *ngx_alloc(size_t size, ngx_log_t *log)
{
    void  *p;

    if (!(p = malloc(size))) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "malloc() " SIZE_T_FMT " bytes failed", size);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "malloc: " PTR_FMT ":" SIZE_T_FMT, p, size);

    return p;
}


void *ngx_calloc(size_t size, ngx_log_t *log)
{
    void  *p;

    p = ngx_alloc(size, log);

    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


#if (HAVE_POSIX_MEMALIGN)

void *ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    void  *p;

    if (posix_memalign(&p, alignment, size) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "posix_memalign() " SIZE_T_FMT " bytes aligned to "
                      SIZE_T_FMT " failed", size, alignment);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: " PTR_FMT ":" SIZE_T_FMT, p, size);

    return p;
}

#elif (HAVE_MEMALIGN)

void *ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    void  *p;

    if (!(p = memalign(alignment, size))) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "memalign() " SIZE_T_FMT " bytes aligned to "
                      SIZE_T_FMT " failed", size, alignment);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: " PTR_FMT ":" SIZE_T_FMT, p, size);

    return p;
}

#endif
