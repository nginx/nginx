
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Intel, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <qatzip.h>
#include <zlib.h>

#define DEFAULT_STRM_BUFF_SZ     (256 * 1024)

typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           sw_fallback_enable;
    ngx_str_t            qatzip_sw;
    ngx_flag_t           no_buffer;

    ngx_hash_t           types;

    ngx_bufs_t           bufs;

    size_t               postpone_qatzipping;
    ngx_int_t            level;
    size_t               strm_buff_sz;
    size_t               chunk_sz;
    size_t               input_sz_thrshold;
    size_t               wait_cnt_thrshold;
    ssize_t              min_length;

    ngx_array_t         *types_keys;
} ngx_http_qatzip_conf_t;


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

    unsigned             inited:1;
    unsigned             last:1;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;
    unsigned             gzheader:1;
    unsigned             buffering:1;
    unsigned             avail_in:1;
    unsigned             avail_out:1;

    size_t               zin;
    size_t               zout;

    uint32_t             crc32;
    QzStream_T           qzstream;
    QzSession_T          qzsession;
    ngx_http_request_t  *request;
} ngx_http_qatzip_ctx_t;


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

struct gztrailer {
    uint32_t  crc32;
    uint32_t  zlen;
};

#else /* NGX_HAVE_BIG_ENDIAN || !NGX_HAVE_NONALIGNED */

struct gztrailer {
    u_char  crc32[4];
    u_char  zlen[4];
};

#endif

QzSession_T * g_last_session = NULL;
static void ngx_http_qatzip_call_qzclose(ngx_cycle_t *cycle)
{
    qzClose(g_last_session);
}



static ngx_int_t ngx_http_qatzip_filter_buffer(ngx_http_qatzip_ctx_t *ctx,
    ngx_chain_t *in);
static ngx_int_t ngx_http_qatzip_filter_stream_init(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);
static ngx_int_t ngx_http_qatzip_filter_gzheader(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);
static ngx_int_t ngx_http_qatzip_filter_add_data(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);
static ngx_int_t ngx_http_qatzip_filter_get_buf(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);
static ngx_int_t ngx_http_qatzip_filter_compress(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);
static ngx_int_t ngx_http_qatzip_filter_end_stream(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);

static void ngx_http_qatzip_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx);

static ngx_int_t ngx_http_qatzip_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_qatzip_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_qatzip_filter_init(ngx_conf_t *cf);
static void *ngx_http_qatzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_qatzip_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_conf_num_bounds_t  ngx_http_qatzip_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 9
};
static ngx_conf_num_bounds_t  ngx_http_qatzip_chunk_size_bounds = {
    ngx_conf_check_num_bounds, 16*1024, 128*1024
};
static ngx_conf_num_bounds_t  ngx_http_qatzip_stream_size_bounds = {
    ngx_conf_check_num_bounds, QZ_STRM_BUFF_MIN_SZ, QZ_STRM_BUFF_MAX_SZ
};
static ngx_conf_num_bounds_t  ngx_http_qatzip_sw_threshold_size_bounds = {
    ngx_conf_check_num_bounds, QZ_COMP_THRESHOLD_MINIMUM, QZ_HW_BUFF_MAX_SZ
};

static ngx_command_t  ngx_http_qatzip_filter_commands[] = {

    { ngx_string("qatzip_sw"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, qatzip_sw),
      NULL },

    { ngx_string("qatzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, bufs),
      NULL },

    { ngx_string("qatzip_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("qatzip_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, level),
      &ngx_http_qatzip_comp_level_bounds },

    { ngx_string("qatzip_stream_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, strm_buff_sz),
      &ngx_http_qatzip_stream_size_bounds },

    { ngx_string("qatzip_chunk_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, chunk_sz),
      &ngx_http_qatzip_chunk_size_bounds },

    { ngx_string("qatzip_sw_threshold"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, input_sz_thrshold),
      &ngx_http_qatzip_sw_threshold_size_bounds },

    { ngx_string("qatzip_wait_cnt_threshold"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, wait_cnt_thrshold),
      NULL },

    { ngx_string("postpone_qatzipping"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, postpone_qatzipping),
      NULL },

    { ngx_string("qatzip_no_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, no_buffer),
      NULL },

    { ngx_string("qatzip_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qatzip_conf_t, min_length),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_qatzip_filter_module_ctx = {
    ngx_http_qatzip_add_variables,           /* preconfiguration */
    ngx_http_qatzip_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_qatzip_create_conf,             /* create location configuration */
    ngx_http_qatzip_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_qatzip_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_qatzip_filter_module_ctx,      /* module context */
    ngx_http_qatzip_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_qatzip_call_qzclose,          /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_qatzip_ratio = ngx_string("qatzip_ratio");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_qatzip_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t       *h;
    ngx_http_qatzip_ctx_t   *ctx;
    ngx_http_qatzip_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_qatzip_filter_module);

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

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_qatzip_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_qatzip_filter_module);

    ctx->request = r;
    ctx->buffering = (conf->postpone_qatzipping != 0);

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
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
ngx_http_qatzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                   rc;
    ngx_uint_t            flush;
    ngx_chain_t          *cl;
    ngx_http_qatzip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qatzip_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http qatzip filter");

    if (ctx->buffering) {
        if (in) {
            switch (ngx_http_qatzip_filter_buffer(ctx, in)) {

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

    if (ngx_http_qatzip_filter_stream_init(r, ctx) != NGX_OK) {
        goto failed;
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
                                (ngx_buf_tag_t) &ngx_http_qatzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = ngx_http_qatzip_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = ngx_http_qatzip_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }


            rc = ngx_http_qatzip_filter_compress(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            ngx_http_qatzip_filter_free_copy_buf(r, ctx);

            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        if (!ctx->gzheader) {
            if (ngx_http_qatzip_filter_gzheader(r, ctx) != NGX_OK) {
                goto failed;
            }
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_http_qatzip_filter_free_copy_buf(r, ctx);

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_qatzip_filter_module);
        ctx->last_out = &ctx->out;

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            goto done;
        }
    }

    /* unreachable */

failed:
    ctx->done = 1;
    ngx_http_qatzip_filter_free_copy_buf(r, ctx);
    rc = NGX_ERROR;

done:
    qzEndStream(&ctx->qzsession, &ctx->qzstream);
    if (ctx->inited) {
        qzTeardownSession(&ctx->qzsession);
        g_last_session = &ctx->qzsession;
        ctx->inited = 0;
    }

    return rc;
}

static ngx_int_t
ngx_http_qatzip_filter_buffer(ngx_http_qatzip_ctx_t *ctx, ngx_chain_t *in)
{
    size_t                 size, buffered;
    ngx_buf_t             *b, *buf;
    ngx_chain_t           *cl, **ll;
    ngx_http_request_t    *r;
    ngx_http_qatzip_conf_t  *conf;

    r = ctx->request;

    r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;

    buffered = 0;
    ll = &ctx->in;

    for (cl = ctx->in; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
        ll = &cl->next;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_qatzip_filter_module);

    while (in) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = in->buf;

        size = b->last - b->pos;
        buffered += size;

        if (b->flush || b->last_buf || buffered > conf->postpone_qatzipping) {
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
            buf->tag = (ngx_buf_tag_t) &ngx_http_qatzip_filter_module;

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
ngx_http_qatzip_filter_stream_init(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx)
{

    int                     rc;
    QzSessionParams_T       params;
    ngx_http_qatzip_conf_t  *conf;

    if (ctx->inited) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_qatzip_filter_module);

    if (QZ_OK != qzGetDefaults(&params)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "Fail to get defulat params.\n");
        return NGX_ERROR;
    }
    params.hw_buff_sz = conf->chunk_sz;
    params.strm_buff_sz = conf->strm_buff_sz;
    params.input_sz_thrshold = conf->input_sz_thrshold;
    params.wait_cnt_thrshold = conf->wait_cnt_thrshold;
    params.data_fmt = QZ_DEFLATE_RAW;
    params.sw_backup = conf->sw_fallback_enable;

    rc = qzInit(&ctx->qzsession, params.sw_backup);
    if (rc != QZ_OK &&
        rc != QZ_DUPLICATE &&
        rc != QZ_NO_HW) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "Fail to init HW with ret: %d.\n", rc);
        return NGX_ERROR;
    }

    rc = qzSetupSession(&ctx->qzsession, &params);
    if (rc != QZ_OK &&
        rc != QZ_NO_HW) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "qzSetupSession for testing %s error, return: %d\n", __func__, rc);
        return NGX_ERROR;
    }

    ctx->last_out = &ctx->out;
    ctx->last = 0;
    ctx->inited = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_qatzip_filter_gzheader(ngx_http_request_t *r, ngx_http_qatzip_ctx_t *ctx)
{
    ngx_buf_t      *b;
    ngx_chain_t    *cl;
    static u_char  gzheader[10] =
                               { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;
    b->pos = gzheader;
    b->last = b->pos + 10;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = ctx->out;
    ctx->out = cl;

    ctx->gzheader = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_qatzip_filter_add_data(ngx_http_request_t *r, ngx_http_qatzip_ctx_t *ctx)
{
    if (ctx->avail_in || ctx->redo) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "qatzip in: %p", ctx->in);

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

    ctx->in_buf = ctx->in->buf;

    if (ctx->in_buf->tag == (ngx_buf_tag_t) &ngx_http_qatzip_filter_module) {
        ctx->copy_buf = ctx->in;
    }

    ctx->in = ctx->in->next;

    ctx->qzstream.in = ctx->in_buf->pos;
    ctx->qzstream.in_sz = ctx->in_buf->last - ctx->in_buf->pos;
    ctx->avail_in = 1;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "qatzip in:%p in_sz:%ud ai:%ud",
                   ctx->qzstream.in, ctx->qzstream.in_sz, ctx->avail_in);

    ctx->last = (ctx->in_buf->last_buf)?1:0;

    if (0 == ctx->qzstream.in_sz) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_qatzip_filter_get_buf(ngx_http_request_t *r, ngx_http_qatzip_ctx_t *ctx)
{
    ngx_http_qatzip_conf_t  *conf;

    if (ctx->avail_out) {
        ctx->qzstream.out = ctx->out_buf->last;
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_qatzip_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_qatzip_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->qzstream.out = ctx->out_buf->last;
    ctx->qzstream.out_sz = conf->bufs.size;
    ctx->avail_out = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_qatzip_filter_compress(ngx_http_request_t *r, ngx_http_qatzip_ctx_t *ctx)
{
    int                    rc;
    ngx_chain_t           *cl;
    ngx_http_qatzip_conf_t  *conf;
    unsigned int orig_in_sz, orig_out_sz;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "qzCompressStream in: in:%p out:%p in_sz:%ud out_sz:%ud last:%d redo:%d",
                 ctx->qzstream.in, ctx->qzstream.out,
                 ctx->qzstream.in_sz, ctx->qzstream.out_sz,
                 ctx->last, ctx->redo);

    orig_in_sz = ctx->qzstream.in_sz;
    orig_out_sz = ctx->qzstream.out_sz;

    rc = qzCompressStream(&ctx->qzsession, &ctx->qzstream, ctx->last);

    if (rc != QZ_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "qzCompressStream() failed: %d, %d", ctx->last, rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "qzCompressStream out: in:%p out:%p in_sz:%ud out_sz:%ud rc:%d",
                   ctx->qzstream.in, ctx->qzstream.out,
                   ctx->qzstream.in_sz, ctx->qzstream.out_sz,
                   rc);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "qatzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    ctx->in_buf->pos += ctx->qzstream.in_sz;
    ctx->out_buf->last += ctx->qzstream.out_sz;
    ctx->avail_in = (ctx->qzstream.in_sz < orig_in_sz)?1:0;
    ctx->avail_out = (ctx->qzstream.out_sz < orig_out_sz)?1:0;
    ctx->zin += ctx->qzstream.in_sz;
    ctx->zout += ctx->qzstream.out_sz;

    if (ctx->avail_in) {
        ctx->qzstream.in_sz = ctx->in_buf->last - ctx->in_buf->pos;
    } else {
        ctx->qzstream.in_sz = 0;
    }
    ctx->qzstream.in = ctx->in_buf->pos;

    if (ctx->avail_out) {
        ctx->qzstream.out_sz = orig_out_sz - ctx->qzstream.out_sz;
    } else {
        ctx->qzstream.out_sz = 0;
    }
    ctx->qzstream.out = ctx->out_buf->last;

    if (0 == ctx->avail_out &&
        ctx->qzstream.pending_out > 0) {
        /*more data pending out */

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

    if (1 == ctx->last && 0 == ctx->avail_in && 0 == ctx->qzstream.pending_in) {

        if (ngx_http_qatzip_filter_end_stream(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_qatzip_filter_module);

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
ngx_http_qatzip_filter_end_stream(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx)
{
    ngx_buf_t         *b;
    ngx_chain_t       *cl;
    struct gztrailer  *trailer;

    ctx->crc32 = ctx->qzstream.crc_32;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "In function %s, ctx crc32 is 0x%X\n", __FUNCTION__, ctx->crc32);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->out_buf;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b = ngx_create_temp_buf(r->pool, 8);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last_buf = 1;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;
    trailer = (struct gztrailer *) b->pos;
    b->last += 8;

#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

    trailer->crc32 = ctx->crc32;
    trailer->zlen = ctx->zin;

#else

    trailer->crc32[0] = (u_char) (ctx->crc32 & 0xff);
    trailer->crc32[1] = (u_char) ((ctx->crc32 >> 8) & 0xff);
    trailer->crc32[2] = (u_char) ((ctx->crc32 >> 16) & 0xff);
    trailer->crc32[3] = (u_char) ((ctx->crc32 >> 24) & 0xff);

    trailer->zlen[0] = (u_char) (ctx->zin & 0xff);
    trailer->zlen[1] = (u_char) ((ctx->zin >> 8) & 0xff);
    trailer->zlen[2] = (u_char) ((ctx->zin >> 16) & 0xff);
    trailer->zlen[3] = (u_char) ((ctx->zin >> 24) & 0xff);

#endif

    ctx->done = 1;

    r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

    return NGX_OK;
}

static void
ngx_http_qatzip_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_qatzip_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        ngx_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}


static ngx_int_t
ngx_http_qatzip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_qatzip_ratio, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_qatzip_ratio_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_qatzip_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t            zint, zfrac;
    ngx_http_qatzip_ctx_t  *ctx;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qatzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

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
ngx_http_qatzip_create_conf(ngx_conf_t *cf)
{
    ngx_http_qatzip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_qatzip_conf_t));
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
    conf->sw_fallback_enable = NGX_CONF_UNSET;
    conf->no_buffer = NGX_CONF_UNSET;

    conf->postpone_qatzipping = NGX_CONF_UNSET_SIZE;
    conf->level = NGX_CONF_UNSET;
    conf->strm_buff_sz = NGX_CONF_UNSET_SIZE;
    conf->chunk_sz = NGX_CONF_UNSET_SIZE;
    conf->input_sz_thrshold = NGX_CONF_UNSET_SIZE;
    conf->wait_cnt_thrshold = NGX_CONF_UNSET_SIZE;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_qatzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_qatzip_conf_t *prev = parent;
    ngx_http_qatzip_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->sw_fallback_enable, prev->sw_fallback_enable, 1);
    ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    ngx_conf_merge_size_value(conf->postpone_qatzipping, prev->postpone_qatzipping,
                              0);
    ngx_conf_merge_value(conf->level, prev->level, 1);
    ngx_conf_merge_size_value(conf->strm_buff_sz, prev->strm_buff_sz,
                                DEFAULT_STRM_BUFF_SZ);
    ngx_conf_merge_size_value(conf->chunk_sz, prev->chunk_sz,
                                QZ_HW_BUFF_SZ);
    ngx_conf_merge_size_value(conf->input_sz_thrshold, prev->input_sz_thrshold,
                                QZ_COMP_THRESHOLD_DEFAULT);
    ngx_conf_merge_size_value(conf->wait_cnt_thrshold, prev->wait_cnt_thrshold,
                                QZ_COMP_THRESHOLD_DEFAULT);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);
    ngx_conf_merge_str_value(conf->qatzip_sw, prev->qatzip_sw, "failover");

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (0 == ngx_strcmp(conf->qatzip_sw.data, "only")) {
        conf->enable = 0;
        conf->sw_fallback_enable = 0;
    } else if (0 == ngx_strcmp(conf->qatzip_sw.data, "failover")) {
        conf->enable = 1;
        conf->sw_fallback_enable = 1;
    } else if (0 == ngx_strcmp(conf->qatzip_sw.data, "no")) {
        conf->enable = 1;
        conf->sw_fallback_enable = 0;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "You must set \"qatzip_sw\" to only\\failover\\no in nginx.conf");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_qatzip_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_qatzip_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_qatzip_body_filter;

    return NGX_OK;
}
