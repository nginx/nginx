
#include <ngx_config.h>
#include <ngx_core.h>


ngx_hunk_t *ngx_create_temp_hunk(ngx_pool_t *pool, size_t size)
{
    ngx_hunk_t *h;

    ngx_test_null(h, ngx_alloc_hunk(pool), NULL);

    ngx_test_null(h->start, ngx_palloc(pool, size), NULL);

    h->pos = h->start;
    h->last = h->start;

    h->file_pos = 0;
    h->file_last = 0;

    h->end = h->last + size;

    h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
    h->file = NULL;
    h->shadow = NULL;

    h->tag = 0;

    return h;
}


ngx_chain_t *ngx_create_chain_of_hunks(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    int           i;
    char         *p;
    ngx_hunk_t   *h;
    ngx_chain_t  *chain, *cl, **ll;

    ngx_test_null(p, ngx_palloc(pool, bufs->num * bufs->size), NULL);

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {
        ngx_test_null(h, ngx_alloc_hunk(pool), NULL);

        h->pos = p;
        h->last = p;
        h->file_pos = 0;
        h->file_last = 0;

        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;

        h->start = p;
        p += bufs->size;
        h->end = p;

        h->file = NULL;
        h->shadow = NULL;
        h->tag = 0;

        ngx_test_null(cl, ngx_alloc_chain_link(pool), NULL);
        cl->hunk = h;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


int ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        ngx_test_null(cl, ngx_alloc_chain_link(pool), NGX_ERROR);

        cl->hunk = in->hunk;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}


void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
                             ngx_chain_t **out, ngx_hunk_tag_t tag)
{
    ngx_chain_t  *te;

    if (*busy == NULL) {
        *busy = *out;

    } else {
        for (te = *busy; /* void */ ; te = te->next) {
            if (te->next == NULL) {
                te->next = *out;
                break;
            }   
        }
    }

    *out = NULL;

    while (*busy) {
        if (ngx_hunk_size((*busy)->hunk) != 0) {
            break;
        }

#if (HAVE_WRITE_ZEROCOPY)
        if ((*busy)->hunk->type & NGX_HUNK_ZEROCOPY_BUSY) {
            break;
        }
#endif

        if ((*busy)->hunk->tag != tag) {
            *busy = (*busy)->next;
            continue;
        }

        (*busy)->hunk->pos = (*busy)->hunk->last = (*busy)->hunk->start;

        te = *busy;
        *busy = (*busy)->next;
        te->next = *free;
        *free = te;
    }
}
