
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


typedef struct {
    int         enable;
    ngx_bufs_t  bufs;
    int         no_buffer;
} ngx_http_gzip_conf_t;


typedef struct {
    ngx_chain_t   *in;
    ngx_chain_t   *free;
    ngx_chain_t   *busy;
    ngx_chain_t   *out;
    ngx_chain_t  **last_out;
    ngx_hunk_t    *in_hunk;
    ngx_hunk_t    *out_hunk;
    int            hunks;

    int            length;
    void          *alloc;

    unsigned       flush:4;
    unsigned       redo:1;

    u_int          crc32;
    z_stream       zstream;
} ngx_http_gzip_ctx_t;


ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx);
static int ngx_http_gzip_filter_init(ngx_cycle_t *cycle);
static void *ngx_http_gzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
                                      void *parent, void *child);


static ngx_command_t  ngx_http_gzip_filter_commands[] = {

    {ngx_string("gzip"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_gzip_conf_t, enable),
     NULL},

    {ngx_string("gzip_buffers"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
     ngx_conf_set_bufs_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_gzip_conf_t, bufs),
     NULL},

    {ngx_string("gzip_no_buffer"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_gzip_conf_t, no_buffer),
     NULL},

    ngx_null_command
};


static ngx_http_module_t  ngx_http_gzip_filter_module_ctx = {
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


static char gzheader[10] = { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };

#if (HAVE_LITTLE_ENDIAN)

struct gztrailer {
    u_int crc32;
    u_int zlen;
};

#else /* HAVE_BIG_ENDIAN */

struct gztrailer {
    unsigned char crc32[4];
    unsigned char zlen[4];
};

#endif



static int (*next_header_filter) (ngx_http_request_t *r);
static int (*next_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static int ngx_http_gzip_header_filter(ngx_http_request_t *r)
{
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (!conf->enable
        || r->headers_out.status != NGX_HTTP_OK
        || r->header_only
        || r->main
        /* TODO: conf->http_version */
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || r->headers_in.accept_encoding == NULL
        || ngx_strstr(r->headers_in.accept_encoding->value.data, "gzip") == NULL
       )
    {
        return next_header_filter(r);
    }

    /* TODO: "text/html" -> custom types */
    if (r->headers_out.content_type
        && ngx_strncasecmp(r->headers_out.content_type->value.data,
                                                          "text/html", 5) != 0)
    {
        return next_header_filter(r);
    }

    ngx_http_create_ctx(r, ctx, ngx_http_gzip_filter_module,
                        sizeof(ngx_http_gzip_ctx_t), NGX_ERROR);

    ngx_test_null(r->headers_out.content_encoding,
                  ngx_push_table(r->headers_out.headers),
                  NGX_ERROR);

    r->headers_out.content_encoding->key.len = 0;
    r->headers_out.content_encoding->key.data = NULL;
    r->headers_out.content_encoding->value.len = 4;
    r->headers_out.content_encoding->value.data = "gzip";

    ctx->length = r->headers_out.content_length;
    r->headers_out.content_length = -1;
    r->filter |= NGX_HTTP_FILTER_NEED_IN_MEMORY;

    return next_header_filter(r);
}


static int ngx_http_gzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                    rc, wbits, mem_level, zin, zout, last;
    struct gztrailer      *trailer;
    ngx_hunk_t            *h;
    ngx_chain_t           *ce;
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL) {
        return next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (ctx->alloc == NULL) {
        wbits = MAX_WBITS;
        mem_level = MAX_MEM_LEVEL - 1;

        if (ctx->length > 0) {

            /* the actual zlib window size is smaller by 262 bytes */

            while (ctx->length < ((1 << (wbits - 1)) - 262)) {
                wbits--;
                mem_level--;
            }
        }

#if 0
        ngx_test_null(ctx->alloc, ngx_alloc(200K, r->log), NGX_ERROR);
#else
        ctx->alloc = (void *) ~NULL;
#endif

        rc = deflateInit2(&ctx->zstream, /**/ 1, Z_DEFLATED,
                          -wbits, mem_level, Z_DEFAULT_STRATEGY);

        if (rc != Z_OK) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "deflateInit2() failed: %d", rc);
            return ngx_http_gzip_error(ctx);
        }

        ngx_test_null(h, ngx_calloc_hunk(r->pool), ngx_http_gzip_error(ctx));

        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_MEMORY;
        h->pos = gzheader;
        h->last = h->pos + 10;

        ngx_test_null(ce, ngx_alloc_chain_entry(r->pool),
                      ngx_http_gzip_error(ctx));
        ce->hunk = h;
        ce->next = NULL;
        ctx->out = ce;
        ctx->last_out = &ce->next;

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

                ctx->zstream.next_in = (unsigned char *) ctx->in_hunk->pos;
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
                                  ngx_create_temp_hunk(r->pool, conf->bufs.size,
                                                       0, 0),
                                  ngx_http_gzip_error(ctx));
                    ctx->out_hunk->type |= NGX_HUNK_RECYCLED;
                    ctx->hunks++;

                } else {
                    break;
                }

                ctx->zstream.next_out = (unsigned char *) ctx->out_hunk->pos;
                ctx->zstream.avail_out = conf->bufs.size;
            }

ngx_log_debug(r->connection->log, "deflate(): %08x %08x %d %d %d" _
              ctx->zstream.next_in _ ctx->zstream.next_out _
              ctx->zstream.avail_in _ ctx->zstream.avail_out _ ctx->flush);

            rc = deflate(&ctx->zstream, ctx->flush);
            if (rc != Z_OK && rc != Z_STREAM_END) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "deflate() failed: %d, %d", ctx->flush, rc);
                return ngx_http_gzip_error(ctx);
            }

ngx_log_debug(r->connection->log, "DEFLATE(): %08x %08x %d %d %d" _
              ctx->zstream.next_in _ ctx->zstream.next_out _
              ctx->zstream.avail_in _ ctx->zstream.avail_out _ rc);

            ctx->in_hunk->pos = (char *) ctx->zstream.next_in;

            if (ctx->zstream.avail_out == 0) {
                ctx->out_hunk->last += conf->bufs.size;
                ngx_add_hunk_to_chain(ce, ctx->out_hunk, r->pool,
                                      ngx_http_gzip_error(ctx));
                *ctx->last_out = ce;
                ctx->last_out = &ce->next;
                ctx->redo = 1;

            } else {
                ctx->out_hunk->last = (char *) ctx->zstream.next_out;
                ctx->redo = 0;

                if (ctx->flush == Z_SYNC_FLUSH) {
                    ctx->out_hunk->type |= NGX_HUNK_FLUSH;
                    ctx->flush = Z_NO_FLUSH;

                    ngx_add_hunk_to_chain(ce, ctx->out_hunk, r->pool,
                                          ngx_http_gzip_error(ctx));
                    *ctx->last_out = ce;
                    ctx->last_out = &ce->next;

                    break;

                } else if (ctx->flush == Z_FINISH) {
                    /* rc == Z_STREAM_END */

                    zin = ctx->zstream.total_in;
                    zout = 10 + ctx->zstream.total_out + 8;

                    rc = deflateEnd(&ctx->zstream);
                    if (rc != Z_OK) {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                      "deflateEnd() failed: %d", rc);
                        return ngx_http_gzip_error(ctx);
                    }

                    ctx->flush = Z_NO_FLUSH;

                    ngx_add_hunk_to_chain(ce, ctx->out_hunk, r->pool,
                                          ngx_http_gzip_error(ctx));
                    *ctx->last_out = ce;
                    ctx->last_out = &ce->next;

                    if (ctx->zstream.avail_out >= 8) {
                        trailer = (struct gztrailer *) ctx->out_hunk->last;
                        ctx->out_hunk->type |= NGX_HUNK_LAST;
                        ctx->out_hunk->last += 8;

                    } else {
                        ngx_test_null(h,
                                      ngx_create_temp_hunk(r->pool, 8, 0, 0),
                                      ngx_http_gzip_error(ctx));

                        h->type |= NGX_HUNK_LAST;

                        ngx_test_null(ce, ngx_alloc_chain_entry(r->pool),
                                      ngx_http_gzip_error(ctx));
                        ce->hunk = h;
                        ce->next = NULL;
                        *ctx->last_out = ce;
                        ctx->last_out = &ce->next;
                        trailer = (struct gztrailer *) h->pos;
                        h->last += 8;
                    }

#if (HAVE_LITTLE_ENDIAN)
                    trailer->crc32 = ctx->crc32;
                    trailer->zlen = zin;
#else
                    /* STUB */
#endif

                    ctx->zstream.avail_in = 0;
                    ctx->zstream.avail_out = 0;
#if 0
                    ngx_free(ctx->alloc);
#endif
                    ngx_http_delete_ctx(r, ngx_http_gzip_filter_module);

                    break;

                } else if (conf->no_buffer && ctx->in == NULL) {
                    ngx_add_hunk_to_chain(ce, ctx->out_hunk, r->pool,
                                          ngx_http_gzip_error(ctx));
                    *ctx->last_out = ce;
                    ctx->last_out = &ce->next;

                    break;
                }
            }
        }

        if (ctx->out == NULL && last != NGX_NONE) {
            return last;
        }

        last = next_body_filter(r, ctx->out);

        if (last == NGX_ERROR) {
            return ngx_http_gzip_error(ctx);
        }

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out);
        ctx->last_out = &ctx->out;
    }
}


ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx)
{
#if 0
    ngx_free(ctx->alloc);
#else
    deflateEnd(&ctx->zstream);
#endif

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    return NGX_ERROR;
}


static int ngx_http_gzip_filter_init(ngx_cycle_t *cycle)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_gzip_header_filter;

    next_body_filter = ngx_http_top_body_filter;
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
/*  conf->bufs.num = 0; */
    conf->no_buffer = NGX_CONF_UNSET;

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
    ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    return NGX_CONF_OK;
}
