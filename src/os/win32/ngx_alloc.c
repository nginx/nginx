
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
