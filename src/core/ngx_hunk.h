#ifndef _NGX_CHUNK_H_INCLUDED_
#define _NGX_CHUNK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_alloc.h>


/* type */
#define NGX_HUNK_TEMP       0x0001
#define NGX_HUNK_MEMORY     0x0002
#define NGX_HUNK_MMAP       0x0004
#define NGX_HUNK_FILE       0x0008
#define NGX_HUNK_FLUSH      0x0010
/* in thread state flush means to write the hunk completely before return
   in event-driven state flush means to start to write the hunk */
#define NGX_HUNK_LAST       0x0020

#define NGX_HUNK_IN_MEMORY  (NGX_HUNK_TEMP | NGX_HUNK_MEMORY | NGX_HUNK_MMAP )
#define NGX_HUNK_TYPE       0x0ffff

/* flags */
#define NGX_HUNK_SHUTDOWN   0x10000
/* can be used with NGX_HUNK_LAST only */


typedef struct ngx_hunk_s ngx_hunk_t;
struct ngx_hunk_s {
    union {
        char    *p;             /* start of current data */
        off_t    f;   
    } pos;
    union {
        char    *p;             /* end of current data */
        off_t    f;   
    } last;
    int          type;
    char        *start;         /* start of hunk */
    char        *end;           /* end of hunk */
    char        *pre_start;     /* start of pre-allocated hunk */
    char        *post_end;      /* end of post-allocated hunk */
    int          tag;
    ngx_file_t   fd;
};

typedef struct ngx_chain_s  ngx_chain_t;
struct ngx_chain_s {
    ngx_hunk_t  *hunk;
    ngx_chain_t *next;
};


ngx_hunk_t *ngx_get_hunk(ngx_pool_t *pool, int size, int before, int after);


#endif /* _NGX_CHUNK_H_INCLUDED_ */
