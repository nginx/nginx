
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           no_buffer;

    ngx_bufs_t           bufs;

    ngx_uint_t           http_version;
    ngx_uint_t           proxied;

    int                  level;
    size_t               wbits;
    size_t               memlevel;
    ssize_t              min_length;
} ngx_http_gzip_conf_t;


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;
    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    off_t                length;

    void                *preallocated;
    char                *free_mem;
    ngx_uint_t           allocated;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
#if 0
    unsigned             pass:1;
    unsigned             blocked:1;
#endif

    size_t               zin;
    size_t               zout;

    uint32_t             crc32;
    z_stream             zstream;
    ngx_http_request_t  *request;
} ngx_http_gzip_ctx_t;


static ngx_int_t ngx_http_gzip_proxied(ngx_http_request_t *r,
                                       ngx_http_gzip_conf_t *conf);
static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items,
                                        u_int size);
static void ngx_http_gzip_filter_free(void *opaque, void *address);
ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx);

static u_char *ngx_http_gzip_log_ratio(ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data);

static ngx_int_t ngx_http_gzip_pre_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_gzip_filter_init(ngx_cycle_t *cycle);
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



static ngx_conf_enum_t  ngx_http_gzip_http_version[] = {
    { ngx_string("1.0"), NGX_HTTP_VERSION_10 },
    { ngx_string("1.1"), NGX_HTTP_VERSION_11 },
    { ngx_null_string, 0 }
};


static ngx_conf_bitmask_t  ngx_http_gzip_proxied_mask[] = {
    { ngx_string("off"), NGX_HTTP_GZIP_PROXIED_OFF },
    { ngx_string("expired"), NGX_HTTP_GZIP_PROXIED_EXPIRED },
    { ngx_string("no-cache"), NGX_HTTP_GZIP_PROXIED_NO_CACHE },
    { ngx_string("no-store"), NGX_HTTP_GZIP_PROXIED_NO_STORE },
    { ngx_string("private"), NGX_HTTP_GZIP_PROXIED_PRIVATE },
    { ngx_string("no_last_modified"), NGX_HTTP_GZIP_PROXIED_NO_LM },
    { ngx_string("no_etag"), NGX_HTTP_GZIP_PROXIED_NO_ETAG },
    { ngx_string("auth"), NGX_HTTP_GZIP_PROXIED_AUTH },
    { ngx_string("any"), NGX_HTTP_GZIP_PROXIED_ANY },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_gzip_filter_commands[] = {

    { ngx_string("gzip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
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
      &ngx_http_gzip_set_window_p },

    { ngx_string("gzip_hash"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, memlevel),
      &ngx_http_gzip_set_hash_p },

    { ngx_string("gzip_no_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, no_buffer),
      NULL },

    { ngx_string("gzip_http_version"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, http_version),
      &ngx_http_gzip_http_version },

    { ngx_string("gzip_proxied"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, proxied),
      &ngx_http_gzip_proxied_mask },

    { ngx_string("gzip_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, min_length),
      NULL },

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


static ngx_int_t ngx_http_gzip_header_filter(ngx_http_request_t *r)
{
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (!conf->enable
        || r->headers_out.status != NGX_HTTP_OK
        || r->header_only
        || r->http_version < conf->http_version
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || r->headers_in.accept_encoding == NULL
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || ngx_strstr(r->headers_in.accept_encoding->value.data, "gzip") == NULL
       )
    {
        return ngx_http_next_header_filter(r);
    }

    /* TODO: "text/html" -> custom types */
    if (r->headers_out.content_type
        && ngx_strncasecmp(r->headers_out.content_type->value.data,
                                                          "text/html", 9) != 0)
    {
        return ngx_http_next_header_filter(r);
    }


    if (r->headers_in.via) {
        if (conf->proxied & NGX_HTTP_GZIP_PROXIED_OFF) {
            return ngx_http_next_header_filter(r);
        }

        if (!(conf->proxied & NGX_HTTP_GZIP_PROXIED_ANY)
            && ngx_http_gzip_proxied(r, conf) == NGX_DECLINED)
        {
            return ngx_http_next_header_filter(r);
        }
    }


    /*
     * if the URL (without the "http://" prefix) is longer than 253 bytes
     * then MSIE 4.x can not handle the compressed stream - it waits too long,
     * hangs up or crashes
     */

    if (r->headers_in.msie4 && r->unparsed_uri.len > 200) {
        return ngx_http_next_header_filter(r);
    }


    ngx_http_create_ctx(r, ctx, ngx_http_gzip_filter_module,
                        sizeof(ngx_http_gzip_ctx_t), NGX_ERROR);
    ctx->request = r;

    r->headers_out.content_encoding = ngx_list_push(&r->headers_out.headers);
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
    r->filter_need_in_memory = 1;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_gzip_proxied(ngx_http_request_t *r,
                                       ngx_http_gzip_conf_t *conf)
{
    time_t  date, expires;

    if (r->headers_in.authorization
        && (conf->proxied & NGX_HTTP_GZIP_PROXIED_AUTH))
    {
        return NGX_OK;
    }

    if (r->headers_out.expires) {

        if (!(conf->proxied & NGX_HTTP_GZIP_PROXIED_EXPIRED)) {
            return NGX_DECLINED;
        }

        expires = ngx_http_parse_time(r->headers_out.expires->value.data,
                                      r->headers_out.expires->value.len);
        if (expires == NGX_ERROR) {
            return NGX_DECLINED;
        }

        if (r->headers_out.date) {
            date = ngx_http_parse_time(r->headers_out.date->value.data,
                                       r->headers_out.date->value.len);
            if (date == NGX_ERROR) {
                return NGX_DECLINED;
            }

        } else {
            date = ngx_time();
        }

        if (expires < date) {
            return NGX_OK;
        }

        return NGX_DECLINED;
    }

    if (r->headers_out.cache_control) {

        if ((conf->proxied & NGX_HTTP_GZIP_PROXIED_NO_CACHE)
            && ngx_strstr(r->headers_out.cache_control->value.data, "no-cache"))
        {
            return NGX_OK;
        }

        if ((conf->proxied & NGX_HTTP_GZIP_PROXIED_NO_STORE)
            && ngx_strstr(r->headers_out.cache_control->value.data, "no-store"))
        {
            return NGX_OK;
        }

        if ((conf->proxied & NGX_HTTP_GZIP_PROXIED_PRIVATE)
            && ngx_strstr(r->headers_out.cache_control->value.data, "private"))
        {
            return NGX_OK;
        }

        return NGX_DECLINED;
    }

    if ((conf->proxied & NGX_HTTP_GZIP_PROXIED_NO_LM)
        && r->headers_out.last_modified)
    {
        return NGX_DECLINED;
    }

    if ((conf->proxied & NGX_HTTP_GZIP_PROXIED_NO_ETAG)
        && r->headers_out.etag)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_gzip_body_filter(ngx_http_request_t *r,
                                           ngx_chain_t *in)
{
    int                    rc, wbits, memlevel, last;
    struct gztrailer      *trailer;
    ngx_buf_t             *b;
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
         * We preallocate a memory for zlib in one buffer (200K-400K), this
         * dicreases a number of malloc() and free() calls and also probably
         * dicreases a number of syscalls (sbrk() or so).
         * Besides we free this memory as soon as the gzipping will complete
         * and do not wait while a whole response will be sent to a client.
         *
         * 8K is for zlib deflate_state, it takes
         *  * 5816 bytes on x86 and sparc64 (32-bit mode)
         *  * 5920 bytes on amd64 and sparc64
         */

        ctx->allocated = 8192 + (1 << (wbits + 2)) + (1 << (memlevel + 9));

        if (!(ctx->preallocated = ngx_palloc(r->pool, ctx->allocated))) {
            return NGX_ERROR;
        }

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

        if (!(b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t)))) {
            return ngx_http_gzip_error(ctx);
        }

        b->memory = 1;
        b->pos = gzheader;
        b->last = b->pos + 10;

        ngx_alloc_link_and_set_buf(cl, b, r->pool, ngx_http_gzip_error(ctx));
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

            /* does zlib need a new data ? */

            if (ctx->zstream.avail_in == 0
                && ctx->flush == Z_NO_FLUSH
                && !ctx->redo)
            {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "gzip in: " PTR_FMT, ctx->in);

                if (ctx->in == NULL) {
                    break;
                }

                ctx->in_buf = ctx->in->buf;
                ctx->in = ctx->in->next;

                ctx->zstream.next_in = ctx->in_buf->pos;
                ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "gzip in_buf:" PTR_FMT " ni:" PTR_FMT " ai:%d",
                               ctx->in_buf,
                               ctx->zstream.next_in, ctx->zstream.avail_in);

                /* STUB */
                if (ctx->in_buf->last < ctx->in_buf->pos) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                  "zstream.avail_in is huge");
                    ctx->done = 1;
                    return NGX_ERROR;
                }
                /**/

                if (ctx->in_buf->last_buf) {
                    ctx->flush = Z_FINISH;

                } else if (ctx->in_buf->flush) {
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
                    ctx->out_buf = ctx->free->buf;
                    ctx->free = ctx->free->next;

                } else if (ctx->bufs < conf->bufs.num) {
                    ctx->out_buf = ngx_create_temp_buf(r->pool,
                                                       conf->bufs.size);
                    if (ctx->out_buf == NULL) {
                        return ngx_http_gzip_error(ctx);
                    }

                    ctx->out_buf->tag = (ngx_buf_tag_t)
                                                  &ngx_http_gzip_filter_module;
                    ctx->out_buf->recycled = 1;
                    ctx->bufs++;

                } else {
#if 0
                    ctx->blocked = 1;
#endif
                    break;
                }

#if 0
                ctx->blocked = 0;
#endif
                ctx->zstream.next_out = ctx->out_buf->pos;
                ctx->zstream.avail_out = conf->bufs.size;
            }

            ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "deflate in: ni:%X no:%X ai:%d ao:%d fl:%d redo:%d",
                           ctx->zstream.next_in, ctx->zstream.next_out,
                           ctx->zstream.avail_in, ctx->zstream.avail_out,
                           ctx->flush, ctx->redo);

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

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "gzip in_buf:" PTR_FMT " pos:" PTR_FMT,
                           ctx->in_buf, ctx->in_buf->pos);


            if (ctx->zstream.next_in) {
                ctx->in_buf->pos = ctx->zstream.next_in;

                if (ctx->zstream.avail_in == 0) {
                    ctx->zstream.next_in = NULL;
                }
            }

            ctx->out_buf->last = ctx->zstream.next_out;

            if (ctx->zstream.avail_out == 0) {

                /* zlib wants to output some more gzipped data */

                ngx_alloc_link_and_set_buf(cl, ctx->out_buf, r->pool,
                                           ngx_http_gzip_error(ctx));
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->redo = 1;

                continue;
            }

            ctx->redo = 0;

            if (ctx->flush == Z_SYNC_FLUSH) {

                ctx->out_buf->flush = 0;
                ctx->flush = Z_NO_FLUSH;

                ngx_alloc_link_and_set_buf(cl, ctx->out_buf, r->pool,
                                           ngx_http_gzip_error(ctx));
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

#if 0
                ctx->pass = 1;
#endif

                break;
            }

            if (rc == Z_STREAM_END) {

                ctx->zin = ctx->zstream.total_in;
                ctx->zout = 10 + ctx->zstream.total_out + 8;

                rc = deflateEnd(&ctx->zstream);

                if (rc != Z_OK) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                  "deflateEnd() failed: %d", rc);
                    return ngx_http_gzip_error(ctx);
                }

                ngx_pfree(r->pool, ctx->preallocated);

                ngx_alloc_link_and_set_buf(cl, ctx->out_buf, r->pool,
                                           ngx_http_gzip_error(ctx));
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                if (ctx->zstream.avail_out >= 8) {
                    trailer = (struct gztrailer *) ctx->out_buf->last;
                    ctx->out_buf->last += 8;
                    ctx->out_buf->last_buf = 1;

                } else {
                    if (!(b = ngx_create_temp_buf(r->pool, 8))) {
                        return ngx_http_gzip_error(ctx);
                    }

                    b->last_buf = 1;

                    ngx_alloc_link_and_set_buf(cl, b, r->pool,
                                               ngx_http_gzip_error(ctx));
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;
                    trailer = (struct gztrailer *) b->pos;
                    b->last += 8;
                }

#if (HAVE_LITTLE_ENDIAN)
                trailer->crc32 = ctx->crc32;
                trailer->zlen = ctx->zin;
#else
                trailer->crc32[0] = ctx->crc32 & 0xff;
                trailer->crc32[1] = (ctx->crc32 >> 8) & 0xff;
                trailer->crc32[2] = (ctx->crc32 >> 16) & 0xff;
                trailer->crc32[3] = (ctx->crc32 >> 24) & 0xff;

                trailer->zlen[0] = ctx->zin & 0xff;
                trailer->zlen[1] = (ctx->zin >> 8) & 0xff;
                trailer->zlen[2] = (ctx->zin >> 16) & 0xff;
                trailer->zlen[3] = (ctx->zin >> 24) & 0xff;
#endif

                ctx->zstream.avail_in = 0;
                ctx->zstream.avail_out = 0;

                ctx->done = 1;
#if 0
                ctx->pass = 1;
#endif

                break;
            }

            if (conf->no_buffer && ctx->in == NULL) {
                ngx_alloc_link_and_set_buf(cl, ctx->out_buf, r->pool,
                                           ngx_http_gzip_error(ctx));
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

#if 0
                ctx->pass = 1;
#endif

                break;
            }
        }

#if 0

        /* OLD CODE */

        if (ctx->out) {
            if (ctx->pass) {
                ctx->pass = 0;

            } else if (last == NGX_AGAIN) {
                return last;
            }

        } else if (ctx->busy->buf && ngx_buf_size(ctx->busy->buf)) {
            if (last != NGX_NONE) {
                return last;
            }

        } else if (ctx->blocked) {
            if (last != NGX_NONE) {
                return last;
            }

        } else {
            if (last == NGX_NONE) {
                return NGX_OK;
            }

            return last;
        }
#endif

        /* NEW CODE */

        if (last == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (ctx->out == NULL && ctx->busy == NULL) {
            return NGX_OK;
        }

        /**/

        last = ngx_http_next_body_filter(r, ctx->out);

        /*
         * we do not check NGX_AGAIN here because the downstream filters
         * may free some buffers and zlib may compress some data into them
         */

        if (last == NGX_ERROR) {
            return ngx_http_gzip_error(ctx);
        }

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                                 (ngx_buf_tag_t) &ngx_http_gzip_filter_module);
        ctx->last_out = &ctx->out;

        if (ctx->done) {
            return last;
        }
    }
}


static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_http_gzip_ctx_t *ctx = opaque;

    void        *p;
    ngx_uint_t   alloc;

    alloc = items * size;
    if (alloc % 512 != 0) {

        /*
         * the zlib deflate_state allocation, it takes about 6K, we allocate 8K
         */

        alloc = (alloc + ngx_pagesize - 1) & ~(ngx_pagesize - 1);
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%d s:%d a:%d p:" PTR_FMT,
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
                              "%" NGX_UINT_T_FMT ".%02" NGX_UINT_T_FMT,
                              zint, zfrac);
}


ngx_inline static int ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx)
{
    deflateEnd(&ctx->zstream);

    ngx_pfree(ctx->request->pool, ctx->preallocated);

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    ctx->done = 1;

    return NGX_ERROR;
}


static ngx_int_t ngx_http_gzip_pre_conf(ngx_conf_t *cf)
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


static ngx_int_t ngx_http_gzip_filter_init(ngx_cycle_t *cycle)
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

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gzip_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    /*

    set by ngx_pcalloc():

    conf->bufs.num = 0;
    conf->proxied = 0;

     */

    conf->enable = NGX_CONF_UNSET;
    conf->no_buffer = NGX_CONF_UNSET;

    conf->http_version = NGX_CONF_UNSET_UINT;

    conf->level = NGX_CONF_UNSET;
    conf->wbits = (size_t) NGX_CONF_UNSET;
    conf->memlevel = (size_t) NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
                                      void *parent, void *child)
{
    ngx_http_gzip_conf_t *prev = parent;
    ngx_http_gzip_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 4, ngx_pagesize);

    ngx_conf_merge_unsigned_value(conf->http_version, prev->http_version,
                                  NGX_HTTP_VERSION_11);
    ngx_conf_merge_bitmask_value(conf->proxied, prev->proxied,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_GZIP_PROXIED_OFF));

    ngx_conf_merge_value(conf->level, prev->level, 1);
    ngx_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    ngx_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 0);
    ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    return NGX_CONF_OK;
}


static char *ngx_http_gzip_set_window(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  wbits, wsize;

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


static char *ngx_http_gzip_set_hash(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  memlevel, hsize;

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
