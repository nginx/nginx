
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name, ngx_log_t *log)
{
    mtx->lock = addr;

    return NGX_OK;
}

#else


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name, ngx_log_t *log)
{
    if (mtx->name) {

        if (ngx_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            mtx->log = log;

            return NGX_OK;
        }

        ngx_shmtx_destory(mtx);
    }

    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;
    mtx->log = log;

    return NGX_OK;
}


void
ngx_shmtx_destory(ngx_shmtx_t *mtx)
{
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, mtx->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


#endif
