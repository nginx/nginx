
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * TODO:
 *     maping name or inheritable handle
 */

ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    0, shm->size, NULL);

    if (shm->handle == NULL) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CreateFileMapping(%uz) failed", shm->size);
        return NGX_ERROR;
    }

    shm->addr = MapViewOfFile(shm->handle, FILE_MAP_WRITE, 0, 0, 0);

    if (shm->addr == NULL) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "MapViewOfFile(%uz) failed", shm->size);

        if (CloseHandle(shm->handle) == 0) {
            ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                          "CloseHandle() failed");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    if (UnmapViewOfFile(shm->addr) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "UnmapViewOfFile(%p) failed", shm->addr);
    }

    if (CloseHandle(shm->handle) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CloseHandle() failed");
    }
}
