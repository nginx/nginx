
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_free_slab_s  ngx_free_slab_t;

typedef struct ngx_free_slab_s {
    ngx_free_slab_t  *next;
}


typedef struct ngx_slab_block_s  ngx_slab_block_t;

typedef struct ngx_slab_block_s {
    ngx_free_slab_t  *free;
    ngx_slab_buf_t   *next;
    size_t            color;
};


typedef struct {
    ngx_slab_buf_t   *blocks;
    size_t            size;

    void             *start;
    uint32_t          map;

    ngx_log_t        *log;
    ngx_free_pool_t   free;
} ngx_slab_pool_t;


#endif /* _NGX_SLAB_H_INCLUDED_ */
