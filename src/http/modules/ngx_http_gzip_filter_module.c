
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           no_buffer;

    ngx_hash_t           types;

    ngx_bufs_t           bufs;

    size_t               postpone_gzipping;
    ngx_int_t            level;
    size_t               wbits;
    size_t               memlevel;
    ssize_t              min_length;

    ngx_array_t         *types_keys;
} ngx_http_gzip_conf_t;


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;

    ngx_chain_t         *copied;
    ngx_chain_t         *copy_buf;

    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    void                *preallocated;
    char                *free_mem;
    ngx_uint_t           allocated;

    int                  wbits;
    int                  memlevel;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;
    unsigned             buffering:1;
    unsigned             zlib_ng:1;
    unsigned             state_allocated:1;

    size_t               zin;
    size_t               zout;

    z_stream             zstream;
    ngx_http_request_t  *request;
} ngx_http_gzip_ctx_t;


static void ngx_http_gzip_filter_memory(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);
static ngx_int_t ngx_http_gzip_filter_buffer(ngx_http_gzip_ctx_t *ctx,
    ngx_chain_t *in);
static ngx_int_t ngx_http_gzip_filter_deflate_start(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);
static ngx_int_t ngx_http_gzip_filter_add_data(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);
static ngx_int_t ngx_http_gzip_filter_get_buf(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);
static ngx_int_t ngx_http_gzip_filter_deflate(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);
static ngx_int_t ngx_http_gzip_filter_deflate_end(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);

static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void ngx_http_gzip_filter_free(void *opaque, void *address);
static void ngx_http_gzip_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx);

static ngx_int_t ngx_http_gzip_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_gzip_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_gzip_filter_init(ngx_conf_t *cf);
static void *ngx_http_gzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_gzip_hash(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_num_bounds_t  ngx_http_gzip_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 9
};

static ngx_conf_post_handler_pt  ngx_http_gzip_window_p = ngx_http_gzip_window;
static ngx_conf_post_handler_pt  ngx_http_gzip_hash_p = ngx_http_gzip_hash;


static ngx_command_t  ngx_http_gzip_filter_commands[] = {

    { ngx_string("gzip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, enable),
      NULL },

    { ngx_string("gzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, bufs),
      NULL },

    { ngx_string("gzip_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("gzip_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, level),
      &ngx_http_gzip_comp_level_bounds },

    { ngx_string("gzip_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, wbits),
      &ngx_http_gzip_window_p },

    { ngx_string("gzip_hash"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, memlevel),
      &ngx_http_gzip_hash_p },

    { ngx_string("postpone_gzipping"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, postpone_gzipping),
      NULL },

    { ngx_string("gzip_no_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, no_buffer),
      NULL },

    { ngx_string("gzip_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, min_length),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_gzip_filter_module_ctx = {
    ngx_http_gzip_add_variables,           /* preconfiguration */
    ngx_http_gzip_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_gzip_create_conf,             /* create location configuration */
    ngx_http_gzip_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_gzip_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_gzip_filter_module_ctx,      /* module context */
    ngx_http_gzip_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_gzip_ratio = ngx_string("gzip_ratio");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_uint_t  ngx_http_gzip_assume_zlib_ng;


static ngx_int_t
ngx_http_gzip_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t       *h;
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (!conf->enable
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || ngx_http_test_content_type(r, &conf->types) == NULL
        || r->header_only)
    {
        return ngx_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

#if (NGX_HTTP_DEGRADATION)
    {
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->gzip_disable_degradation && ngx_http_degraded(r)) {
        return ngx_http_next_header_filter(r);
    }
    }
#endif

    if (!r->gzip_tested) {
        if (ngx_http_gzip_ok(r) != NGX_OK) {
            return ngx_http_next_header_filter(r);
        }

    } else if (!r->gzip_ok) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gzip_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_gzip_filter_module);

    ctx->request = r;
    ctx->buffering = (conf->postpone_gzipping != 0);

    ngx_http_gzip_filter_memory(r, ctx);

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_gzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                   rc;
    ngx_uint_t            flush;
    ngx_chain_t          *cl;
    ngx_http_gzip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http gzip filter");

    if (ctx->buffering) {

        /*
         * With default memory settings zlib starts to output gzipped data
         * only after it has got about 90K, so it makes sense to allocate
         * zlib memory (200-400K) only after we have enough data to compress.
         * Although we copy buffers, nevertheless for not big responses
         * this allows to allocate zlib memory, to compress and to output
         * the response in one step using hot CPU cache.
         */

        if (in) {
            switch (ngx_http_gzip_filter_buffer(ctx, in)) {

            case NGX_OK:
                return NGX_OK;

            case NGX_DONE:
                in = NULL;
                break;

            default:  /* NGX_ERROR */
                goto failed;
            }

        } else {
            ctx->buffering = 0;
        }
    }

    if (ctx->preallocated == NULL) {
        if (ngx_http_gzip_filter_deflate_start(r, ctx) != NGX_OK) {
            goto failed;
        }
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }

        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_gzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = ngx_http_gzip_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = ngx_http_gzip_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }


            rc = ngx_http_gzip_filter_deflate(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            ngx_http_gzip_filter_free_copy_buf(r, ctx);

            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_http_gzip_filter_free_copy_buf(r, ctx);

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_gzip_filter_module);
        ctx->last_out = &ctx->out;

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    if (ctx->preallocated) {
        deflateEnd(&ctx->zstream);

        ngx_pfree(r->pool, ctx->preallocated);
    }

    ngx_http_gzip_filter_free_copy_buf(r, ctx);

    return NGX_ERROR;
}


static void
ngx_http_gzip_filter_memory(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
{
    int                    wbits, memlevel;
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    wbits = conf->wbits;
    memlevel = conf->memlevel;

    if (r->headers_out.content_length_n > 0) {

        /* the actual zlib window size is smaller by 262 bytes */

        while (r->headers_out.content_length_n < ((1 << (wbits - 1)) - 262)) {
            wbits--;
            memlevel--;
        }

        if (memlevel < 1) {
            memlevel = 1;
        }
    }

    ctx->wbits = wbits;
    ctx->memlevel = memlevel;

    /*
     * We preallocate a memory for zlib in one buffer (200K-400K), this
     * decreases a number of malloc() and free() calls and also probably
     * decreases a number of syscalls (sbrk()/mmap() and so on).
     * Besides we free the memory as soon as a gzipping will complete
     * and do not wait while a whole response will be sent to a client.
     *
     * 8K is for zlib deflate_state, it takes
     *  *) 5816 bytes on i386 and sparc64 (32-bit mode)
     *  *) 5920 bytes on amd64 and sparc64
     *
     * A zlib variant from Intel (https://github.com/jtkukunas/zlib)
     * uses additional 16-byte padding in one of window-sized buffers.
     */

    if (!ngx_http_gzip_assume_zlib_ng) {
        ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
                         + (1 << (memlevel + 9));

    } else {
        /*
         * Another zlib variant, https://github.com/zlib-ng/zlib-ng.
         * It used to force window bits to 13 for fast compression level,
         * uses (64 + sizeof(void*)) additional space on all allocations
         * for alignment, 16-byte padding in one of window-sized buffers,
         * and 128K hash.
         */

        if (conf->level == 1) {
            wbits = ngx_max(wbits, 13);
        }

        ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
                         + 131072 + (1 << (memlevel + 8))
                         + 4 * (64 + sizeof(void*));
        ctx->zlib_ng = 1;
    }
}


static ngx_int_t
ngx_http_gzip_filter_buffer(ngx_http_gzip_ctx_t *ctx, ngx_chain_t *in)
{
    size_t                 size, buffered;
    ngx_buf_t             *b, *buf;
    ngx_chain_t           *cl, **ll;
    ngx_http_request_t    *r;
    ngx_http_gzip_conf_t  *conf;

    r = ctx->request;

    r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;

    buffered = 0;
    ll = &ctx->in;

    for (cl = ctx->in; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
        ll = &cl->next;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    while (in) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = in->buf;

        size = b->last - b->pos;
        buffered += size;

        if (b->flush || b->last_buf || buffered > conf->postpone_gzipping) {
            ctx->buffering = 0;
        }

        if (ctx->buffering && size) {

            buf = ngx_create_temp_buf(r->pool, size);
            if (buf == NULL) {
                return NGX_ERROR;
            }

            buf->last = ngx_cpymem(buf->pos, b->pos, size);
            b->pos = b->last;

            buf->last_buf = b->last_buf;
            buf->tag = (ngx_buf_tag_t) &ngx_http_gzip_filter_module;

            cl->buf = buf;

        } else {
            cl->buf = b;
        }

        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return ctx->buffering ? NGX_OK : NGX_DONE;
}


static ngx_int_t
ngx_http_gzip_filter_deflate_start(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx)
{
    int                    rc;
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    ctx->preallocated = ngx_palloc(r->pool, ctx->allocated);
    if (ctx->preallocated == NULL) {
        return NGX_ERROR;
    }

    ctx->free_mem = ctx->preallocated;

    ctx->zstream.zalloc = ngx_http_gzip_filter_alloc;
    ctx->zstream.zfree = ngx_http_gzip_filter_free;
    ctx->zstream.opaque = ctx;

    rc = deflateInit2(&ctx->zstream, (int) conf->level, Z_DEFLATED,
                      ctx->wbits + 16, ctx->memlevel, Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "deflateInit2() failed: %d", rc);
        return NGX_ERROR;
    }

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return NGX_OK;
}


static ngx_int_t
ngx_http_gzip_filter_add_data(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    if (ctx->copy_buf) {

        /*
         * to avoid CPU cache trashing we do not free() just quit buf,
         * but postpone free()ing after zlib compressing and data output
         */

        ctx->copy_buf->next = ctx->copied;
        ctx->copied = ctx->copy_buf;
        ctx->copy_buf = NULL;
    }

    cl = ctx->in;
    ctx->in_buf = cl->buf;
    ctx->in = cl->next;

    if (ctx->in_buf->tag == (ngx_buf_tag_t) &ngx_http_gzip_filter_module) {
        ctx->copy_buf = cl;

    } else {
        ngx_free_chain(r->pool, cl);
    }

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf) {
        ctx->flush = Z_FINISH;

    } else if (ctx->in_buf->flush) {
        ctx->flush = Z_SYNC_FLUSH;

    } else if (ctx->zstream.avail_in == 0) {
        /* ctx->flush == Z_NO_FLUSH */
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_gzip_filter_get_buf(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
{
    ngx_chain_t           *cl;
    ngx_http_gzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (ctx->free) {

        cl = ctx->free;
        ctx->out_buf = cl->buf;
        ctx->free = cl->next;

        ngx_free_chain(r->pool, cl);

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_gzip_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->zstream.next_out = ctx->out_buf->pos;
    ctx->zstream.avail_out = conf->bufs.size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_gzip_filter_deflate(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
{
    int                    rc;
    ngx_buf_t             *b;
    ngx_chain_t           *cl;
    ngx_http_gzip_conf_t  *conf;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "deflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                 ctx->zstream.next_in, ctx->zstream.next_out,
                 ctx->zstream.avail_in, ctx->zstream.avail_out,
                 ctx->flush, ctx->redo);

    rc = deflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "deflate() failed: %d, %d", ctx->flush, rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->zstream.next_in) {
        ctx->in_buf->pos = ctx->zstream.next_in;

        if (ctx->zstream.avail_in == 0) {
            ctx->zstream.next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->zstream.next_out;

    if (ctx->zstream.avail_out == 0 && rc != Z_STREAM_END) {

        /* zlib wants to output some more gzipped data */

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return NGX_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == Z_SYNC_FLUSH) {

        ctx->flush = Z_NO_FLUSH;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {

            b = ngx_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

        } else {
            ctx->zstream.avail_out = 0;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        return NGX_OK;
    }

    if (rc == Z_STREAM_END) {

        if (ngx_http_gzip_filter_deflate_end(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (conf->no_buffer && ctx->in == NULL) {

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_gzip_filter_deflate_end(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx)
{
    int           rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ctx->zin = ctx->zstream.total_in;
    ctx->zout = ctx->zstream.total_out;

    rc = deflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "deflateEnd() failed: %d", rc);
        return NGX_ERROR;
    }

    ngx_pfree(r->pool, ctx->preallocated);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ctx->out_buf;

    if (ngx_buf_size(b) == 0) {
        b->temporary = 0;
    }

    b->last_buf = 1;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    ctx->done = 1;

    r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

    return NGX_OK;
}


static void *
ngx_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_http_gzip_ctx_t *ctx = opaque;

    void        *p;
    ngx_uint_t   alloc;

    alloc = items * size;

    if (items == 1 && alloc % 512 != 0 && alloc < 8192
        && !ctx->state_allocated)
    {
        /*
         * The zlib deflate_state allocation, it takes about 6K,
         * we allocate 8K.  Other allocations are divisible by 512.
         */

        ctx->state_allocated = 1;

        alloc = 8192;
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%ud s:%ud a:%ui p:%p",
                       items, size, alloc, p);

        return p;
    }

    if (ctx->zlib_ng) {
        ngx_log_error(NGX_LOG_ALERT, ctx->request->connection->log, 0,
                      "gzip filter failed to use preallocated memory: "
                      "%ud of %ui", items * size, ctx->allocated);

    } else {
        ngx_http_gzip_assume_zlib_ng = 1;
    }

    p = ngx_palloc(ctx->request->pool, items * size);

    return p;
}


static void
ngx_http_gzip_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_gzip_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %p", address);
#endif
}


static void
ngx_http_gzip_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_gzip_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        ngx_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}


static ngx_int_t
ngx_http_gzip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_gzip_ratio, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_gzip_ratio_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_gzip_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t            zint, zfrac;
    ngx_http_gzip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN + 3);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    zint = (ngx_uint_t) (ctx->zin / ctx->zout);
    zfrac = (ngx_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);

    if ((ctx->zin * 1000 / ctx->zout) % 10 > 4) {

        /* the rounding, e.g., 2.125 to 2.13 */

        zfrac++;

        if (zfrac > 99) {
            zint++;
            zfrac = 0;
        }
    }

    v->len = ngx_sprintf(v->data, "%ui.%02ui", zint, zfrac) - v->data;

    return NGX_OK;
}


static void *
ngx_http_gzip_create_conf(ngx_conf_t *cf)
{
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->no_buffer = NGX_CONF_UNSET;

    conf->postpone_gzipping = NGX_CONF_UNSET_SIZE;
    conf->level = NGX_CONF_UNSET;
    conf->wbits = NGX_CONF_UNSET_SIZE;
    conf->memlevel = NGX_CONF_UNSET_SIZE;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_gzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_gzip_conf_t *prev = parent;
    ngx_http_gzip_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    ngx_conf_merge_size_value(conf->postpone_gzipping, prev->postpone_gzipping,
                              0);
    ngx_conf_merge_value(conf->level, prev->level, 1);
    ngx_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    ngx_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_gzip_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_gzip_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_gzip_body_filter;

    return NGX_OK;
}


static char *
ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return NGX_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}


static char *
ngx_http_gzip_hash(ngx_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  memlevel, hsize;

    memlevel = 9;

    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;

            return NGX_CONF_OK;
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
}
