
/*
 * Copyright (C) Igor Sysoev
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

#if (NGX_LINUX)

ngx_int_t
ngx_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    struct crypt_data   cd;

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = ngx_strlen(value);

        *encrypted = ngx_palloc(pool, len);
        if (*encrypted) {
            ngx_memcpy(*encrypted, value, len + 1);
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

#else

ngx_int_t
ngx_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    ngx_int_t   rc;

#if (NGX_THREADS && NGX_NONREENTRANT_CRYPT)

    /* crypt() is a time consuming funtion, so we only try to lock */

    if (ngx_mutex_trylock(ngx_crypt_mutex) != NGX_OK) {
        return NGX_AGAIN;
    }

#endif

    rc = NGX_ERROR;

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = ngx_strlen(value);

        *encrypted = ngx_palloc(pool, len);
        if (*encrypted) {
            ngx_memcpy(*encrypted, value, len + 1);
            rc = NGX_OK;
        }
    }

#if (NGX_THREADS && NGX_NONREENTRANT_CRYPT)
    ngx_mutex_unlock(ngx_crypt_mutex);
#endif

    return rc;
}

#endif

#endif /* NGX_CRYPT */
