
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Solaris has thread-safe crypt()
 * Linux has crypt_r(); "struct crypt_data" is more than 128K
 * FreeBSD needs the mutex to protect crypt()
 *
 * TODO:
 *     ngx_crypt_init() to init mutex
 */


#if (NGX_CRYPT)

#if (NGX_HAVE_GNU_CRYPT_R)

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    struct crypt_data   cd;

    cd.initialized = 0;
#ifdef __GLIBC__
    /* work around the glibc bug */
    cd.current_salt[0] = ~salt[0];
#endif

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = ngx_strlen(value) + 1;

        *encrypted = ngx_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(*encrypted, value, len);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_CRIT, pool->log, ngx_errno, "crypt_r() failed");

    return NGX_ERROR;
}

#else

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    ngx_err_t   err;

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = ngx_strlen(value) + 1;

        *encrypted = ngx_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(*encrypted, value, len);
        return NGX_OK;
    }

    err = ngx_errno;

    ngx_log_error(NGX_LOG_CRIT, pool->log, err, "crypt() failed");

    return NGX_ERROR;
}

#endif

#endif /* NGX_CRYPT */
