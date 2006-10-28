
/*
 * Copyright (C) Igor Sysoev
 */


typedef struct ngx_slab_map_s  ngx_slab_map_t;

struct ngx_http_slab_map_s {
    uintptr_t        mask;
    ngx_slab_elt_t  *next;
};


typedef struct {
    ngx_slab_elt_t  *slabs;

    ngx_slab_elt_t  *map;
    size_t           map_size;

    size_t           size;

} ngx_slab_t;


void *
ngx_slab_init(ngx_slab_pool_t *pool, size_t size)
{
    slab->map_size = (slab->size + ngx_pagesize - 1)
                          / (ngx_pagesize / sizeof(ngx_slab_map_t));


    return NULL;
}


void *
ngx_slab_alloc(ngx_slab_t *pool, size_t size)
{
    n = size - 1;


    return NULL;
}
