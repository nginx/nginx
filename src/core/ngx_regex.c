
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
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


static ngx_inline void
ngx_regex_malloc_init(ngx_pool_t *pool)
{
#if (NGX_THREADS)
    ngx_core_tls_t  *tls;

    if (ngx_threaded) {
        tls = ngx_thread_get_tls(ngx_core_tls_key);
        tls->pool = pool;
        return;
    }

#endif

    ngx_pcre_pool = pool;
}


static ngx_inline void
ngx_regex_malloc_done(void)
{
#if (NGX_THREADS)
    ngx_core_tls_t  *tls;

    if (ngx_threaded) {
        tls = ngx_thread_get_tls(ngx_core_tls_key);
        tls->pool = NULL;
        return;
    }

#endif

    ngx_pcre_pool = NULL;
}


ngx_int_t
ngx_regex_compile(ngx_regex_compile_t *rc)
{
    int           n, erroff;
    char         *p;
    const char   *errstr;
    ngx_regex_t  *re;

    ngx_regex_malloc_init(rc->pool);

    re = pcre_compile((const char *) rc->pattern.data, (int) rc->options,
                      &errstr, &erroff, NULL);

    /* ensure that there is no current pool */
    ngx_regex_malloc_done();

    if (re == NULL) {
        if ((size_t) erroff == rc->pattern.len) {
           rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\"",
                               errstr, &rc->pattern)
                      - rc->err.data;

        } else {
           rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\" at \"%s\"",
                               errstr, &rc->pattern, rc->pattern.data + erroff)
                      - rc->err.data;
        }

        return NGX_ERROR;
    }

    rc->regex = re;

    n = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &rc->captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_CAPTURECOUNT) failed: %d";
        goto failed;
    }

    if (rc->captures == 0) {
        return NGX_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMECOUNT, &rc->named_captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMECOUNT) failed: %d";
        goto failed;
    }

    if (rc->named_captures == 0) {
        return NGX_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMEENTRYSIZE, &rc->name_size);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMEENTRYSIZE) failed: %d";
        goto failed;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMETABLE, &rc->names);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMETABLE) failed: %d";
        goto failed;
    }

    return NGX_OK;

failed:

    rc->err.len = ngx_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
                  - rc->err.data;
    return NGX_OK;
}


ngx_int_t
ngx_regex_exec_array(ngx_array_t *a, ngx_str_t *s, ngx_log_t *log)
{
    ngx_int_t         n;
    ngx_uint_t        i;
    ngx_regex_elt_t  *re;

    re = a->elts;

    for (i = 0; i < a->nelts; i++) {

        n = ngx_regex_exec(re[i].regex, s, NULL, 0);

        if (n == NGX_REGEX_NO_MATCHED) {
            continue;
        }

        if (n < 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          ngx_regex_exec_n " failed: %i on \"%V\" using \"%s\"",
                          n, s, re[i].name);
            return NGX_ERROR;
        }

        /* match */

        return NGX_OK;
    }

    return NGX_DECLINED;
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
