
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


typedef struct {
    int  hunk_size;
    int  max_hunks;
    int  no_buffer;
} ngx_http_gzip_conf_t;


typedef struct {
    ngx_chain_t   *in;
    ngx_chain_t   *free;
    ngx_chain_t   *busy;
    ngx_chain_t   *out;
    ngx_chain_t  **last_out;
    ngx_hunk_t    *in_hunk;
    ngx_hunk_t    *out_hunk;
    void          *alloc;

    z_stream       zstream;
} ngx_http_gzip_ctx_t;


static int ngx_http_gzip_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_gzip_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_gzip_filter_module = {
    NGX_MODULE,
    &ngx_http_gzip_filter_module_ctx,      /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_gzip_filter_init,             /* init module */
    NULL                                   /* init child */
};


static const char gzheader[10] =
                               { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };


static int (*next_header_filter) (ngx_http_request_t *r);
static int (*next_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static int ngx_http_gzip_header_filter(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK
        || (ngx_strncasecmp(r->headers_out.content_type->value.data,
                            "text/", 5) != 0)
    {
        return next_header_filter(r);
    }

    ngx_http_create_ctx(r, ctx, ngx_http_gzip_filter_module,
                        sizeof(ngx_http_gzip_filter_ctx_t), NGX_ERROR);

    ctx->length = r->headers_out.content_length;
    r->headers_out.content_length = -1;

    return next_header_filter(r);
}


static int ngx_http_gzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL) {
        next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (ctx->alloc == NULL) {
#if 0
        ngx_test_null(ctx->alloc, ngx_alloc(200K, r->log), NGX_ERROR);
#else
        ctx->alloc = ~NULL;
#endif
        rc = deflateInit2(&ctx->zstream, /**/ 1, Z_DEFLATED,
                          /**/ -MAX_WBITS, /**/ MAX_MEM_LEVEL - 1,
                          Z_DEFAULT_STRATEGY);

        if (rc != Z_OK) {
            ngx_log_error(NGX_LOG_ALERT, r->log, 0,
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
        add_to_chain(ctx->in, in)
    }

    for ( ;; ) {

        for ( ;; ) {

            if (ctx->flush == Z_NO_FLUSH
                && ctx->zstream->avail_in == 0
                && ctx->in)
             {
                ctx->in_hunk = ctx->in->hunk;
                ctx->in = ctx->in->next;

                ctx->zstream->next_in = ctx->in_hunk->pos;
                ctx->zstream->avail_in = ctx->in_hunk->last - ctx->in_hunk->pos;

                if (ctx->in_hunk->type & NGX_HUNK_LAST) {
                    ctx->flush = Z_FINISH;

                } else if (ctx->in_hunk->type & NGX_HUNK_FLUSH) {
                    ctx->flush = Z_SYNC_FINISH;
                }
            }

            if (ctx->zstream->avail_out == 0) {
                if (ctx->free) {
                    ctx->out_hunk = ctx->free->hunk;
                    ctx->free = ctx->free->next;

                } else if (ctx->max_hunks < ctx->cur_hunks) {
                    ngx_test_null(ctx->out_hunk,
                                  ngx_create_temp_hunk(r->pool, conf->size,
                                                       0, 0),
                                  ngx_http_gzip_error(ctx));
                    ctx->cur_hunks++;

                } else {
                     break;
                }

                ctx->zstream->next_out = ctx->out_hunk->pos;
                ctx->zstream->avail_out = conf->size;
            }

            rc = deflate(ctx->zstream, ctx->flush);
            if (rc != Z_OK && rc != Z_STREAM_END) {
                ngx_log_error(NGX_LOG_ALERT, r->log, 0,
                              "deflate() failed: %d, %d", ctx->flush, rc);
                return ngx_http_gzip_error(ctx);
            }

            ctx->in_hunk->pos = ctx->zstream->next_in;

            if (rc == Z_STREAM_END) {
                deflateEnd(ctx->zstream);
                ngx_free();
            }

            if (ctx->zstream->avail_out == 0) {
                ctx->out_hunk->last += conf->size;
                ngx_add_hunk_to_chain(*ctx->last_out, ctx->out_hunk,
                                      r->pool, ngx_http_gzip_error(ctx));

            } else {
                ctx->out_hunk->last = ctx->zstream->next_out;

                if (ctx->flush == Z_SYNC_FLUSH) {
                    ctx->out_hunk->type |= NGX_HUNK_FLUSH;
                    ngx_add_hunk_to_chain(*ctx->last_out, ctx->out_hunk,
                                          r->pool, ngx_http_gzip_error(ctx));
                    ctx->flush = Z_NO_FLUSH;
                    break;

                } else if (ctx->flush == Z_FINISH) {
                    ctx->out_hunk->type |= NGX_HUNK_LAST;
                    ngx_add_hunk_to_chain(*ctx->last_out, ctx->out_hunk,
                                          r->pool, ngx_http_gzip_error(ctx));
                    break;

                } else if (conf->no_buffer && ctx->in == NULL) {
                    ngx_add_hunk_to_chain(*ctx->last_out, ctx->out_hunk,
                                          r->pool, ngx_http_gzip_error(ctx));
                    break;
                }
            }
        }

        if (next_body_filter(r, ctx->out) == NGX_ERROR) {
            return ngx_http_gzip_error(ctx);
        }

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out);
    }
}


ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx)
{
#if 0
    ngx_free(ctx->alloc);
#endif

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
