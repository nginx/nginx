#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts;
    ngx_uint_t        nelts;
    ngx_list_part_t  *next;
};


typedef struct {
    ngx_list_part_t  *last;
    ngx_list_part_t   part;
    size_t            size;
    ngx_uint_t        nalloc;
    ngx_pool_t       *pool;
} ngx_list_t;


#define ngx_init_list(l, p, n, s, rc)                                        \
    if (!(l.part.elts = ngx_palloc(p, n * s))) {                             \
        return rc;                                                           \
    }                                                                        \
    l.part.nelts = 0; l.part.next = NULL;                                    \
    l.last = &l.part; l.size = s; l.nalloc = n; l.pool = p;


#define ngx_iterate_list(p, i)                                               \
            for ( ;; i++) {                                                  \
                if (i >= p->nelts) {                                         \
                    if (p->next == NULL) {                                   \
                        break;                                               \
                    }                                                        \
                    p = p->next; i = 0;                                      \
                }


void *ngx_push_list(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
