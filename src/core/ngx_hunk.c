
#include <ngx_config.h>
#include <ngx_core.h>


ngx_hunk_t *ngx_create_temp_hunk(ngx_pool_t *pool, int size,
                                 int before, int after)
{
    ngx_hunk_t *h;

    ngx_test_null(h, ngx_palloc(pool, sizeof(ngx_hunk_t)), NULL);

    ngx_test_null(h->pre_start, ngx_palloc(pool, size + before + after), NULL);

    h->start = h->pos = h->last = h->pre_start + before;
    h->file_pos = h->file_last = 0;
    h->end = h->last + size;
    h->post_end = h->end + after;

    h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
    h->file = NULL;
    h->shadow = NULL;

    h->tag = 0;

    return h;
}

ngx_hunk_t *ngx_create_hunk_before(ngx_pool_t *pool, ngx_hunk_t *hunk, int size)
{
    ngx_hunk_t *h;

    ngx_test_null(h, ngx_palloc(pool, sizeof(ngx_hunk_t)), NULL);

    if (hunk->type & NGX_HUNK_TEMP && hunk->pos - hunk->pre_start >= size) {
        /* keep hunk->start unchanged - used in restore */
        h->pre_start = hunk->pre_start;
        h->end = h->post_end = hunk->pre_start = hunk->pos;
        h->start = h->pos = h->last = h->end - size;
        h->file_pos = h->file_last = 0;

        h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
        h->file = NULL;
        h->shadow = NULL;

        h->tag = 0;

    } else {
        ngx_test_null(h->pre_start, ngx_palloc(pool, size), NULL);
        h->start = h->pos = h->last = h->pre_start;
        h->end = h->post_end = h->start + size;
        h->file_pos = h->file_last = 0;

        h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
        h->file = NULL;
        h->shadow = NULL;

        h->tag = 0;
    }

    return h;
}

ngx_hunk_t *ngx_create_hunk_after(ngx_pool_t *pool, ngx_hunk_t *hunk, int size)
{
    ngx_hunk_t *h;

    ngx_test_null(h, ngx_palloc(pool, sizeof(ngx_hunk_t)), NULL);

    if (hunk->type & NGX_HUNK_TEMP
        && hunk->last == hunk->end
        && hunk->post_end - hunk->end >= size)
    {
        h->post_end = hunk->post_end;
        h->pre_start = h->start = h->pos = h->last = hunk->post_end =
                                                                hunk->last;
        h->file_pos = h->file_last = 0;

        h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
        h->file = NULL;
        h->shadow = NULL;

        h->tag = 0;

    } else {
        ngx_test_null(h->pre_start, ngx_palloc(pool, size), NULL);
        h->start = h->pos = h->last = h->pre_start;
        h->end = h->post_end = h->start + size;
        h->file_pos = h->file_last = 0;

        h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
        h->file = NULL;
        h->shadow = NULL;

        h->tag = 0;
    }

    return h;
}


int ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **ch, ngx_chain_t *in)
{
    ngx_chain_t  *ce, **le;

    le = ch;

    for (ce = *ch; ce; ce = ce->next) {
        le = &ce->next;
    }

    while (in) {
        ngx_test_null(ce, ngx_alloc_chain_entry(pool), NGX_ERROR);

        ce->hunk = in->hunk;
        ce->next = NULL;
        *le = ce;
        le = &ce->next;
        in = in->next;
    }

    return NGX_OK;
}


void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
                             ngx_chain_t **out)
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
        if ((*busy)->hunk->pos != (*busy)->hunk->last) {
            break;
        }

#if (HAVE_WRITE_ZEROCOPY)
        if ((*busy)->hunk->type & NGX_HUNK_ZEROCOPY_BUSY) {
            break;
        }
#endif

        (*busy)->hunk->pos = (*busy)->hunk->last = (*busy)->hunk->start;

        te = *busy;
        *busy = (*busy)->next;
        te->next = *free;
        *free = te;
    }
}
