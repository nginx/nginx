
#include <ngx_file.h>
#include <ngx_hunk.h>


ngx_hunk_t *ngx_get_hunk(ngx_pool_t *pool, int size, int before, int after)
{
    ngx_hunk_t *h = ngx_palloc(pool, sizeof(ngx_hunk_t));

#ifndef OFF_EQUAL_PTR
    h->pos.file = h->last.file = 0;
#endif

    h->pre_start = ngx_palloc(pool, size + before + after);
    h->start = h->pos.mem = h->last.mem = h->pre_start + before;
    h->end = h->last.mem + size;
    h->post_end = h->end + after;

    h->type = NGX_HUNK_TEMP;
    h->tag = 0;
    h->fd = (ngx_file_t) -1;

    return h;
}
    
ngx_hunk_t *ngx_get_hunk_before(ngx_pool_t *pool, ngx_hunk_t *hunk, int size)
{    
    ngx_hunk_t *h = ngx_palloc(pool, sizeof(ngx_hunk_t));

#ifndef OFF_EQUAL_PTR
    h->pos.file = h->last.file = 0;
#endif
 
    if (hunk->type & NGX_HUNK_TEMP && hunk->pos.mem - hunk->pre_start >= size) {
        /* keep hunk->start unchanged - used in restore */
        h->pre_start = hunk->pre_start;
        h->end = h->post_end = hunk->pre_start = hunk->pos.mem;
        h->start = h->pos.mem = h->last.mem = h->end - size;

        h->type = NGX_HUNK_TEMP;
        h->tag = 0;
        h->fd = (ngx_file_t) -1;

    } else {
        h->pre_start = h->start = h->pos.mem = h->last.mem
                                                      = ngx_palloc(pool, size);
        h->end = h->post_end = h->start + size;

        h->type = NGX_HUNK_TEMP;
        h->tag = 0;
        h->fd = (ngx_file_t) -1;
    }

    return h;
}

ngx_hunk_t *ngx_get_hunk_after(ngx_pool_t *pool, ngx_hunk_t *hunk, int size)
{
    ngx_hunk_t *h = ngx_palloc(pool, sizeof(ngx_hunk_t));

#ifndef OFF_EQUAL_PTR
    h->pos.file = h->last.file = 0;
#endif

    if (hunk->type & NGX_HUNK_TEMP
        && hunk->last.mem == hunk->end
        && hunk->post_end - hunk->end >= size)
    {
        h->post_end = hunk->post_end;
        h->pre_start = h->start = h->pos.mem = h->last.mem = hunk->post_end =
                                                                hunk->last.mem;
        h->type = NGX_HUNK_TEMP;
        h->tag = 0;
        h->fd = (ngx_file_t) -1;

    } else {
        h->pre_start = h->start = h->pos.mem = h->last.mem =
                                                        ngx_palloc(pool, size);
        h->end = h->post_end = h->start + size;

        h->type = NGX_HUNK_TEMP;
        h->tag = 0;
        h->fd = (ngx_file_t) -1;
    }

    return h;
}
