
#include <ngx_config.h>
#include <ngx_hunk.h>


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
    h->tag = 0;
    h->file = NULL;

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
        h->tag = 0;
        h->file = NULL;

    } else {
        ngx_test_null(h->pre_start, ngx_palloc(pool, size), NULL);
        h->start = h->pos = h->last = h->pre_start; 
        h->end = h->post_end = h->start + size;
        h->file_pos = h->file_last = 0;

        h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
        h->tag = 0;
        h->file = NULL;
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
        h->tag = 0;
        h->file = NULL;

    } else {
        ngx_test_null(h->pre_start, ngx_palloc(pool, size), NULL);
        h->start = h->pos = h->last = h->pre_start; 
        h->end = h->post_end = h->start + size;
        h->file_pos = h->file_last = 0;

        h->type = NGX_HUNK_TEMP|NGX_HUNK_IN_MEMORY;
        h->tag = 0;
        h->file = NULL;
    }

    return h;
}
