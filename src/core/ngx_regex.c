
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void * ngx_libc_cdecl ngx_regex_malloc(size_t size);
static void ngx_libc_cdecl ngx_regex_free(void *p);


static ngx_pool_t  *ngx_pcre_pool;


void
ngx_regex_init(void)
{
    pcre_malloc = ngx_regex_malloc;
    pcre_free = ngx_regex_free;
}


ngx_regex_t *
ngx_regex_compile(ngx_str_t *pattern, ngx_int_t options, ngx_pool_t *pool,
    ngx_str_t *err)
{
    int              erroff;
    const char      *errstr;
    ngx_regex_t     *re;
#if (NGX_THREADS)
    ngx_core_tls_t  *tls;

#if (NGX_SUPPRESS_WARN)
    tls = NULL;
#endif

    if (ngx_threaded) {
        tls = ngx_thread_get_tls(ngx_core_tls_key);
        tls->pool = pool;
    } else {
        ngx_pcre_pool = pool;
    }

#else

    ngx_pcre_pool = pool;

#endif

    re = pcre_compile((const char *) pattern->data, (int) options,
                      &errstr, &erroff, NULL);

    if (re == NULL) {
       if ((size_t) erroff == pattern->len) {
           ngx_snprintf(err->data, err->len - 1,
                        "pcre_compile() failed: %s in \"%s\"%Z",
                        errstr, pattern->data);
        } else {
           ngx_snprintf(err->data, err->len - 1,
                        "pcre_compile() failed: %s in \"%s\" at \"%s\"%Z",
                        errstr, pattern->data, pattern->data + erroff);
        }
    }

    /* ensure that there is no current pool */

#if (NGX_THREADS)
    if (ngx_threaded) {
        tls->pool = NULL;
    } else {
        ngx_pcre_pool = NULL;
    }
#else
    ngx_pcre_pool = NULL;
#endif

    return re;
}


ngx_int_t
ngx_regex_capture_count(ngx_regex_t *re)
{
    int  rc, n;

    n = 0;

    rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &n);

    if (rc < 0) {
        return (ngx_int_t) rc;
    }

    return (ngx_int_t) n;
}


ngx_int_t
ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures, ngx_int_t size)
{
    int  rc;

    rc = pcre_exec(re, NULL, (const char *) s->data, s->len, 0, 0,
                   captures, size);

    if (rc == -1) {
        return NGX_REGEX_NO_MATCHED;
    }

    return rc;
}


static void * ngx_libc_cdecl
ngx_regex_malloc(size_t size)
{
    ngx_pool_t      *pool;
#if (NGX_THREADS)
    ngx_core_tls_t  *tls;

    if (ngx_threaded) {
        tls = ngx_thread_get_tls(ngx_core_tls_key);
        pool = tls->pool;
    } else {
        pool = ngx_pcre_pool;
    }
#else
    pool = ngx_pcre_pool;
#endif

    if (pool) {
        return ngx_palloc(pool, size);
    }

    return NULL;
}


static void ngx_libc_cdecl
ngx_regex_free(void *p)
{
    return;
}
