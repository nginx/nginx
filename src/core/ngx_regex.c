
#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_regex_malloc(size_t size);
static void ngx_regex_free(void *p);


/* THREADS: this pool should be private for each thread */
static ngx_pool_t  *ngx_pcre_pool;


void ngx_regex_init()
{
    pcre_malloc = ngx_regex_malloc;
    pcre_free = ngx_regex_free;
}


ngx_regex_t *ngx_regex_compile(ngx_str_t *pattern, ngx_int_t options,
                               ngx_pool_t *pool, ngx_str_t *err)
{
    int           erroff;
    const char   *errstr;
    ngx_regex_t  *re;

    ngx_pcre_pool = pool;

    re = pcre_compile(pattern->data, (int) options, &errstr, &erroff, NULL);

    if (re == NULL) {
       if ((size_t) erroff == pattern->len) {
           ngx_snprintf(err->data, err->len - 1,
                        "pcre_compile() failed: %s in \"%s\"",
                        errstr, pattern->data);
        } else {
           ngx_snprintf(err->data, err->len - 1,
                        "pcre_compile() failed: %s in \"%s\" at \"%s\"",
                        errstr, pattern->data, pattern->data + erroff);
        }
    }

    return re;
}


ngx_int_t ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s)
{
    int  rc;

    rc = pcre_exec(re, NULL, s->data, s->len, 0, 0, NULL, 0);

    if (rc == -1) {
        return NGX_DECLINED;
    }

    return rc;
}


static void *ngx_regex_malloc(size_t size)
{
    return ngx_palloc(ngx_pcre_pool, size);
}


static void ngx_regex_free(void *p)
{
    return;
}
