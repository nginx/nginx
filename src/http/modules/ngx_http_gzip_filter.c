
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           no_buffer;

    ngx_bufs_t           bufs;

    int                  level;
    int                  wbits;
    int                  memlevel;
} ngx_http_gzip_conf_t;


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;
    ngx_hunk_t          *in_hunk;
    ngx_hunk_t          *out_hunk;
    int                  hunks;

    off_t                length;

    void                *preallocated;
    char                *free_mem;
    int                  allocated;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;

    size_t               zin;
    size_t               zout;

    uint32_t             crc32;
    z_stream             zstream;
    ngx_http_request_t  *request;
} ngx_http_gzip_ctx_t;


static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items,
                                        u_int size);
static void ngx_http_gzip_filter_free(void *opaque, void *address);

ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx);

static u_char *ngx_http_gzip_log_ratio(ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data);

static int ngx_http_gzip_pre_conf(ngx_conf_t *cf);
static int ngx_http_gzip_filter_init(ngx_cycle_t *cycle);
static void *ngx_http_gzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
                                      void *parent, void *child);
static char *ngx_http_gzip_set_window(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_gzip_set_hash(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_num_bounds_t  ngx_http_gzip_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 9
};

static ngx_conf_post_handler_pt  ngx_http_gzip_set_window_p =
                                                      ngx_http_gzip_set_window;
static ngx_conf_post_handler_pt  ngx_http_gzip_set_hash_p =
                                                        ngx_http_gzip_set_hash;



static ngx_command_t  ngx_http_gzip_filter_commands[] = {

    { ngx_string("gzip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, enable),
      NULL},

    { ngx_string("gzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, bufs),
      NULL},

    { ngx_string("gzip_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, level),
      &ngx_http_gzip_comp_level_bounds},

    { ngx_string("gzip_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, wbits),
      &ngx_http_gzip_set_window_p},

    { ngx_string("gzip_hash"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, memlevel),
      &ngx_http_gzip_set_hash_p},

    { ngx_string("gzip_no_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, no_buffer),
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_gzip_filter_module_ctx = {
    ngx_http_gzip_pre_conf,                /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_gzip_create_conf,             /* create location configuration */
    ngx_http_gzip_merge_conf,              /* merge location configuration */
};


ngx_module_t  ngx_http_gzip_filter_module = {
    NGX_MODULE,
    &ngx_http_gzip_filter_module_ctx,      /* module context */
    ngx_http_gzip_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_gzip_filter_init,             /* init module */
    NULL                                   /* init child */
};


static ngx_http_log_op_name_t ngx_http_gzip_log_fmt_ops[] = {
    { ngx_string("gzip_ratio"), NGX_INT32_LEN + 3, ngx_http_gzip_log_ratio },
    { ngx_null_string, 0, NULL }
};



static u_char  gzheader[10] = { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };

#if (HAVE_LITTLE_ENDIAN)

struct gztrailer {
    uint32_t  crc32;
    uint32_t  zlen;
};

#else /* HAVE_BIG_ENDIAN */

struct gztrailer {
    u_char  crc32[4];
    u_char  zlen[4];
};

#endif


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static int ngx_http_gzip_header_filter(ngx_http_request_t *r)
{
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (!conf->enable
        || r->headers_out.status != NGX_HTTP_OK
        || r->header_only
        /* TODO: conf->http_version */
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || r->headers_in.accept_encoding == NULL
        || ngx_strstr(r->headers_in.accept_encoding->value.data, "gzip") == NULL
       )
    {
        return ngx_http_next_header_filter(r);
    }

    /* TODO: "text/html" -> custom types */
    if (r->headers_out.content_type
        && ngx_strncasecmp(r->headers_out.content_type->value.data,
                                                          "text/html", 5) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_create_ctx(r, ctx, ngx_http_gzip_filter_module,
                        sizeof(ngx_http_gzip_ctx_t), NGX_ERROR);
    ctx->request = r;

    r->headers_out.content_encoding =
                    ngx_http_add_header(&r->headers_out, ngx_http_headers_out);
    if (r->headers_out.content_encoding == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_encoding->key.len = sizeof("Content-Encoding") - 1;
    r->headers_out.content_encoding->key.data = (u_char *) "Content-Encoding";
    r->headers_out.content_encoding->value.len = sizeof("gzip") - 1;
    r->headers_out.content_encoding->value.data = (u_char *) "gzip";

    ctx->length = r->headers_out.content_length_n;
    r->headers_out.content_length_n = -1;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->key.len = 0;
        r->headers_out.content_length = NULL;
    }
    r->filter |= NGX_HTTP_FILTER_NEED_IN_MEMORY;

    return ngx_http_next_header_filter(r);
}


static int ngx_http_gzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                    rc, wbits, memlevel, last;
    struct gztrailer      *trailer;
    ngx_hunk_t            *h;
    ngx_chain_t           *cl;
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (ctx->preallocated == NULL) {
        wbits = conf->wbits;
        memlevel = conf->memlevel;

        if (ctx->length > 0) {

            /* the actual zlib window size is smaller by 262 bytes */

            while (ctx->length < ((1 << (wbits - 1)) - 262)) {
                wbits--;
                memlevel--;
            }
        }

        /*
         * We preallocate a memory for zlib in one hunk (200K-400K), this
         * dicreases a number of malloc() and free() calls and also probably
         * dicreases a number of syscalls.
         * Besides we free() this memory as soon as the gzipping will complete
         * and do not wait while a whole response will be sent to a client.
         *
         * 8K is for zlib deflate_state (~6K).
         *
         * TODO: 64-bit, round to PAGE_SIZE, autoconf of deflate_state size
         */

        ctx->allocated = 8192 + (1 << (wbits + 2)) + (1 << (memlevel + 9));

        ngx_test_null(ctx->preallocated, ngx_palloc(r->pool, ctx->allocated),
                      NGX_ERROR);
        ctx->free_mem = ctx->preallocated;

        ctx->zstream.zalloc = ngx_http_gzip_filter_alloc;
        ctx->zstream.zfree = ngx_http_gzip_filter_free;
        ctx->zstream.opaque = ctx;

        rc = deflateInit2(&ctx->zstream, conf->level, Z_DEFLATED,
                          -wbits, memlevel, Z_DEFAULT_STRATEGY);

        if (rc != Z_OK) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "deflateInit2() failed: %d", rc);
            return ngx_http_gzip_error(ctx);
        }

        ngx_test_null(h, ngx_calloc_hunk(r->pool), ngx_http_gzip_error(ctx));

        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY;
        h->pos = gzheader;
        h->last = h->pos + 10;

        ngx_alloc_link_and_set_hunk(cl, h, r->pool, ngx_http_gzip_error(ctx));
        ctx->out = cl;
        ctx->last_out = &cl->next;

        ctx->crc32 = crc32(0L, Z_NULL, 0);
        ctx->flush = Z_NO_FLUSH;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            return ngx_http_gzip_error(ctx);
        }
    }

    last = NGX_NONE;

    for ( ;; ) {

        for ( ;; ) {

            /* is there a data to gzip ? */

            if (ctx->zstream.avail_in == 0
                && ctx->flush == Z_NO_FLUSH
                && !ctx->redo) {

                if (ctx->in == NULL) {
                    break;
                }

                ctx->in_hunk = ctx->in->hunk;
                ctx->in = ctx->in->next;

                ctx->zstream.next_in = (u_char *) ctx->in_hunk->pos;
                ctx->zstream.avail_in = ctx->in_hunk->last - ctx->in_hunk->pos;

                if (ctx->in_hunk->type & NGX_HUNK_LAST) {
                    ctx->flush = Z_FINISH;

                } else if (ctx->in_hunk->type & NGX_HUNK_FLUSH) {
                    ctx->flush = Z_SYNC_FLUSH;
                }

                if (ctx->zstream.avail_in == 0) {
                    if (ctx->flush == Z_NO_FLUSH) {
                        continue;
                    }

                } else {
                    ctx->crc32 = crc32(ctx->crc32, ctx->zstream.next_in,
                                       ctx->zstream.avail_in);
                }
            }

            /* is there a space for the gzipped data ? */

            if (ctx->zstream.avail_out == 0) {
                if (ctx->free) {
                    ctx->out_hunk = ctx->free->hunk;
                    ctx->free = ctx->free->next;

                } else if (ctx->hunks < conf->bufs.num) {
                    ngx_test_null(ctx->out_hunk,
                                 ngx_create_temp_hunk(r->pool, conf->bufs.size),
                                 ngx_http_gzip_error(ctx));
                    ctx->out_hunk->tag = (ngx_hunk_tag_t)
                                                  &ngx_http_gzip_filter_module;
                    ctx->out_hunk->type |= NGX_HUNK_RECYCLED;
                    ctx->hunks++;

                } else {
                    break;
                }

                ctx->zstream.next_out = (u_char *) ctx->out_hunk->pos;
                ctx->zstream.avail_out = conf->bufs.size;
            }

            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "deflate in: ni:%X no:%X ai:%d ao:%d fl:%d",
                           ctx->zstream.next_in, ctx->zstream.next_out,
                           ctx->zstream.avail_in, ctx->zstream.avail_out,
                           ctx->flush);

            rc = deflate(&ctx->zstream, ctx->flush);
            if (rc != Z_OK && rc != Z_STREAM_END) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "deflate() failed: %d, %d", ctx->flush, rc);
                return ngx_http_gzip_error(ctx);
            }

            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "deflate out: ni:%X no:%X ai:%d ao:%d rc:%d",
                           ctx->zstream.next_in, ctx->zstream.next_out,
                           ctx->zstream.avail_in, ctx->zstream.avail_out,
                           rc);

            ctx->in_hunk->pos = ctx->zstream.next_in;
            ctx->out_hunk->last = ctx->zstream.next_out;

            if (ctx->zstream.avail_out == 0) {
                ngx_alloc_link_and_set_hunk(cl, ctx->out_hunk, r->pool,
                                            ngx_http_gzip_error(ctx));
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
                ctx->redo = 1;

            } else {
                ctx->redo = 0;

                if (ctx->flush == Z_SYNC_FLUSH) {
                    ctx->out_hunk->type |= NGX_HUNK_FLUSH;
                    ctx->flush = Z_NO_FLUSH;

                    ngx_alloc_link_and_set_hunk(cl, ctx->out_hunk, r->pool,
                                                ngx_http_gzip_error(ctx));
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    break;

                } else if (ctx->flush == Z_FINISH) {

                    /* rc == Z_STREAM_END */

                    ctx->zin = ctx->zstream.total_in;
                    ctx->zout = 10 + ctx->zstream.total_out + 8;

                    rc = deflateEnd(&ctx->zstream);
                    if (rc != Z_OK) {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                      "deflateEnd() failed: %d", rc);
                        return ngx_http_gzip_error(ctx);
                    }

                    ngx_pfree(r->pool, ctx->preallocated);

                    ctx->flush = Z_NO_FLUSH;

                    ngx_alloc_link_and_set_hunk(cl, ctx->out_hunk, r->pool,
                                                ngx_http_gzip_error(ctx));
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    if (ctx->zstream.avail_out >= 8) {
                        trailer = (struct gztrailer *) ctx->out_hunk->last;
                        ctx->out_hunk->type |= NGX_HUNK_LAST;
                        ctx->out_hunk->last += 8;

                    } else {
                        ngx_test_null(h,
                                      ngx_create_temp_hunk(r->pool, 8),
                                      ngx_http_gzip_error(ctx));

                        h->type |= NGX_HUNK_LAST;

                        ngx_alloc_link_and_set_hunk(cl, h, r->pool,
                                                    ngx_http_gzip_error(ctx));
                        *ctx->last_out = cl;
                        ctx->last_out = &cl->next;
                        trailer = (struct gztrailer *) h->pos;
                        h->last += 8;
                    }

#if (HAVE_LITTLE_ENDIAN)
                    trailer->crc32 = ctx->crc32;
                    trailer->zlen = ctx->zin;
#else
                    /* STUB */
#endif

                    ctx->zstream.avail_in = 0;
                    ctx->zstream.avail_out = 0;

                    ctx->done = 1;

#if 0
                    ngx_http_delete_ctx(r, ngx_http_gzip_filter_module);
#endif

                    break;

                } else if (conf->no_buffer && ctx->in == NULL) {
                    ngx_alloc_link_and_set_hunk(cl, ctx->out_hunk, r->pool,
                                                ngx_http_gzip_error(ctx));
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    break;
                }
            }
        }

        if (ctx->out == NULL && last != NGX_NONE) {
            return last;
        }

        last = ngx_http_next_body_filter(r, ctx->out);

        if (last == NGX_ERROR) {
            return ngx_http_gzip_error(ctx);
        }

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                                (ngx_hunk_tag_t) &ngx_http_gzip_filter_module);
        ctx->last_out = &ctx->out;
    }
}


static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_http_gzip_ctx_t *ctx = opaque;

    int    alloc;
    void  *p;

    alloc = items * size;
    if (alloc % 512 != 0) {

        /* we allocate 8K for zlib deflate_state (~6K) */
        /* TODO: PAGE_SIZE */

        alloc = (alloc + 4095) & ~4095;
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%d s:%d a:%d p:%08X",
                       items, size, alloc, p);

        return p;
    }

    ngx_log_error(NGX_LOG_ALERT, ctx->request->connection->log, 0,
                  "gzip filter failed to use preallocated memory: %d of %d",
                  items * size, ctx->allocated);

    p = ngx_palloc(ctx->request->pool, items * size);

    return p;
}


static void ngx_http_gzip_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_gzip_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %X", address);
#endif
}


static u_char *ngx_http_gzip_log_ratio(ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data)
{
    ngx_uint_t            zint, zfrac;
    ngx_http_gzip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        *buf = '-';
        return buf + 1;
    }

#if 0
    return buf + ngx_snprintf((char *) buf, NGX_INT32_LEN + 4, "%.2f",
                              (float) ctx->zin / ctx->zout);
#endif

    /* we prefer do not use FPU */

    zint = (ngx_uint_t) (ctx->zin / ctx->zout);
    zfrac = (ngx_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);

    if ((ctx->zin * 1000 / ctx->zout) %10 > 4) {
        if (++zfrac > 99) {
            zint++;
            zfrac = 0;
        }
    }

    return buf + ngx_snprintf((char *) buf, NGX_INT32_LEN + 4,
                              "%d.%02d", zint, zfrac);
}


ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx)
{
    deflateEnd(&ctx->zstream);

    ngx_pfree(ctx->request->pool, ctx->preallocated);

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    return NGX_ERROR;
}


static int ngx_http_gzip_pre_conf(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_gzip_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->op = NULL;

    op = ngx_http_log_fmt_ops;

    for (op = ngx_http_log_fmt_ops; op->op; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->op;
        }
    }

    op->op = (ngx_http_log_op_pt) ngx_http_gzip_log_fmt_ops;

    return NGX_OK;
}


static int ngx_http_gzip_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_gzip_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_gzip_body_filter;

    return NGX_OK;
}


static void *ngx_http_gzip_create_conf(ngx_conf_t *cf)
{
    ngx_http_gzip_conf_t  *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_gzip_conf_t)),
                  NGX_CONF_ERROR);

    conf->enable = NGX_CONF_UNSET;
    conf->no_buffer = NGX_CONF_UNSET;

 /* conf->bufs.num = 0; */

    conf->level = NGX_CONF_UNSET;
    conf->wbits = NGX_CONF_UNSET;
    conf->memlevel = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
                                      void *parent, void *child)
{
    ngx_http_gzip_conf_t *prev = parent;
    ngx_http_gzip_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 4,
                              /* STUB: PAGE_SIZE */ 4096);
    ngx_conf_merge_value(conf->level, prev->level, 1);
    ngx_conf_merge_value(conf->wbits, prev->wbits, MAX_WBITS);
    ngx_conf_merge_value(conf->memlevel, prev->memlevel, MAX_MEM_LEVEL - 1);
    ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    return NGX_CONF_OK;
}


static char *ngx_http_gzip_set_window(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  wbits, wsize;


ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "WBITS: %d", *np);

    wbits = 15;
    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;
ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "WBITS: %d", *np);
            return NULL;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}


static char *ngx_http_gzip_set_hash(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  memlevel, hsize;


ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "MEMLEVEL: %d", *np);

    memlevel = 9;
    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;
ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "MEMLEVEL: %d", *np);
            return NULL;
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
}
