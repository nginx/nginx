#ifndef _NGX_CHUNK_H_INCLUDED_
#define _NGX_CHUNK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_file.h>
#include <ngx_alloc.h>


/* hunk type */

/* the hunk is in memory */
#define NGX_HUNK_IN_MEMORY  0x0001
/* the hunk's content can be changed */
#define NGX_HUNK_TEMP       0x0002
/* the hunk's content is in cache and can not be changed */
#define NGX_HUNK_MEMORY     0x0004
/* the hunk's content is mmap()ed and can not be changed */
#define NGX_HUNK_MMAP       0x0008

#define NGX_HUNK_RECYCLED   0x0010

/* the hunk is in file */
#define NGX_HUNK_FILE       0x0100

/* hunk flags */

/* in thread state flush means to write the hunk completely before return */
/* in event state flush means to start to write the hunk */
#define NGX_HUNK_FLUSH      0x1000
/* last hunk */
#define NGX_HUNK_LAST       0x2000




typedef struct ngx_hunk_s ngx_hunk_t;
struct ngx_hunk_s {
#if 0
    union {
        char    *mem;           /* start of current data */
        off_t    file;   
    } pos;
    union {
        char    *mem;           /* end of current data */
        off_t    file;   
    } last;
#endif

    char        *pos;
    char        *last;
    off_t        file_pos;
    off_t        file_last;

    int          type;
    char        *start;         /* start of hunk */
    char        *end;           /* end of hunk */
    char        *pre_start;     /* start of pre-allocated hunk */
    char        *post_end;      /* end of post-allocated hunk */
    int          tag;
    ngx_file_t  *file;
};



typedef struct ngx_chain_s  ngx_chain_t;
struct ngx_chain_s {
    ngx_hunk_t  *hunk;
    ngx_chain_t *next;
};


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_hunk_in_memory_only(h)                                           \
         ((h->type & (NGX_HUNK_IN_MEMORY|NGX_HUNK_FILE)) == NGX_HUNK_IN_MEMORY)


ngx_hunk_t *ngx_create_temp_hunk(ngx_pool_t *pool, int size,
                                 int before, int after);

#define ngx_create_chain_entry(pool) ngx_palloc(pool, sizeof(ngx_chain_t))

#define ngx_add_hunk_to_chain(chain, h, pool, error)                         \
            do {                                                             \
                ngx_test_null(chain, ngx_create_chain_entry(pool), error);   \
                chain->hunk = h;                                             \
                chain->next = NULL;                                          \
            } while (0);


#endif /* _NGX_CHUNK_H_INCLUDED_ */
