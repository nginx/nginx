
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    if (!(b = ngx_calloc_buf(pool))) {
        return NULL;
    }

    if (!(b->start = ngx_palloc(pool, size))) {
        return NULL;
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    /*

    b->file_pos = 0;
    b->file_last = 0;

    b->file = NULL;
    b->shadow = NULL;

    b->tag = 0;

     */

    return b;
}


ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;

    if (!(p = ngx_palloc(pool, bufs->num * bufs->size))) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {
        if (!(b = ngx_calloc_buf(pool))) {
            return NULL;
        }

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

        /*
        b->file_pos = 0;
        b->file_last = 0;

        b->file = NULL;
        b->shadow = NULL;
        b->tag = 0;
        */

        if (!(cl = ngx_alloc_chain_link(pool))) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
                             ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        ngx_test_null(cl, ngx_alloc_chain_link(pool), NGX_ERROR);

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}


void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
                             ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *tl;

    if (*busy == NULL) {
        *busy = *out;

    } else {
        for (tl = *busy; /* void */ ; tl = tl->next) {
            if (tl->next == NULL) {
                tl->next = *out;
                break;
            }
        }
    }

    *out = NULL;

    while (*busy) {
        if (ngx_buf_size((*busy)->buf) != 0) {
            break;
        }

#if (HAVE_WRITE_ZEROCOPY)
        if ((*busy)->buf->zerocopy_busy) {
            break;
        }
#endif

        if ((*busy)->buf->tag != tag) {
            *busy = (*busy)->next;
            continue;
        }

        (*busy)->buf->pos = (*busy)->buf->last = (*busy)->buf->start;

        tl = *busy;
        *busy = (*busy)->next;
        tl->next = *free;
        *free = tl;
    }
}
