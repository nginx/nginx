
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    u_char    *name;
    uint64_t   size;

    name = ngx_alloc(shm->name.len + 2 + sizeof(NGX_INT32_LEN), shm->log);
    if (name == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(name, "%V_%s%Z", &shm->name, ngx_unique);

    ngx_set_errno(0);

    size = shm->size;

    shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    (u_long) (size >> 32),
                                    (u_long) (size & 0xffffffff),
                                    (char *) name);

    if (shm->handle == NULL) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CreateFileMapping(%uz, %s) failed",
                      shm->size, shm->name.data);
        goto failed;
    }

    if (ngx_errno == ERROR_ALREADY_EXISTS) {
        shm->exists = 1;
    }

    shm->addr = MapViewOfFile(shm->handle, FILE_MAP_WRITE, 0, 0, 0);

    if (shm->addr != NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                  "MapViewOfFile(%uz) failed", shm->size);

    if (CloseHandle(shm->handle) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CloseHandle() failed");
    }

failed:

    ngx_free(name);

    return NGX_ERROR;
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
