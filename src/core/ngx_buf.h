#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if 0
/* the buf type */

/* the buf's content is in memory */
#define NGX_HUNK_IN_MEMORY    0x0001
/* the buf's content can be changed */
#define NGX_HUNK_TEMP         0x0002
/* the buf's content is in cache and can not be changed */
#define NGX_HUNK_MEMORY       0x0004
#define NGX_HUNK_MMAP         0x0008

/* the buf's content is recycled */
#define NGX_HUNK_RECYCLED     0x0010

/* the buf's content is in a file */
#define NGX_HUNK_FILE         0x0020

#define NGX_HUNK_STORAGE      (NGX_HUNK_IN_MEMORY                            \
                               |NGX_HUNK_TEMP|NGX_HUNK_MEMORY|NGX_HUNK_MMAP  \
                               |NGX_HUNK_RECYCLED|NGX_HUNK_FILE)

/* the buf flags */

/* in thread state flush means to write the buf completely before return */
/* in event state flush means to start to write the buf */
#define NGX_HUNK_FLUSH        0x0100

/* the last buf */
#define NGX_HUNK_LAST         0x0200


#define NGX_HUNK_PREREAD      0x2000
#define NGX_HUNK_LAST_SHADOW  0x4000
#define NGX_HUNK_TEMP_FILE    0x8000
#endif


typedef void *                   ngx_buf_tag_t;

typedef struct ngx_buf_s         ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos;
    u_char          *last;
    off_t            file_pos;
    off_t            file_last;

    int              type;
    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag;
    ngx_file_t      *file;
    ngx_buf_t       *shadow;


    /* the buf's content can be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and can not be changed
     */
    unsigned         memory:1;

    /* the buf's content is mmap()ed and can not be changed */
    unsigned         mmap:1;
    unsigned         recycled:1;
    unsigned         in_file:1;
    unsigned         flush:1;
    unsigned         last_buf:1;

    unsigned         last_shadow:1;
    unsigned         temp_file:1;

    unsigned         zerocopy_busy:1;

    /* STUB */ int   num;
};


typedef struct ngx_chain_s       ngx_chain_t;

struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef int  (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *out);

typedef struct {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile;
    unsigned                     need_in_memory;
    unsigned                     need_in_temp;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
} ngx_output_chain_ctx_t;


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR
#define NGX_CHAIN_AGAIN     (ngx_chain_t *) NGX_AGAIN


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)
#define ngx_buf_special(b)                                                   \
        ((b->flush || b->last_buf) && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_size(b)                                                      \
        (ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos):                 \
                                (size_t) (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))


#define ngx_alloc_chain_link(pool) ngx_palloc(pool, sizeof(ngx_chain_t))


#define ngx_alloc_link_and_set_buf(chain, b, pool, error)                    \
            do {                                                             \
                ngx_test_null(chain, ngx_alloc_chain_link(pool), error);     \
                chain->buf = b;                                              \
                chain->next = NULL;                                          \
            } while (0);


#define ngx_chain_add_link(chain, last, cl)                                  \
            if (chain) {                                                     \
                *last = cl;                                                  \
            } else {                                                         \
                chain = cl;                                                  \
            }                                                                \
            last = &cl->next


ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *data, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
                             ngx_chain_t *in);
void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
                             ngx_chain_t **out, ngx_buf_tag_t tag);


#endif /* _NGX_BUF_H_INCLUDED_ */
