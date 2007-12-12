
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_NO_CHARSET    -2
#define NGX_HTTP_CHARSET_VAR   0x10000

/* 1 byte length and up to 3 bytes for the UTF-8 encoding of the UCS-2 */
#define NGX_UTF_LEN             4

#define NGX_HTML_ENTITY_LEN     (sizeof("&#1114111;") - 1)


typedef struct {
    u_char                    **tables;
    ngx_str_t                   name;

    unsigned                    length:16;
    unsigned                    utf8:1;
} ngx_http_charset_t;


typedef struct {
    ngx_int_t                   src;
    ngx_int_t                   dst;
} ngx_http_charset_recode_t;


typedef struct {
    ngx_int_t                   src;
    ngx_int_t                   dst;
    u_char                     *src2dst;
    u_char                     *dst2src;
} ngx_http_charset_tables_t;


typedef struct {
    ngx_array_t                 charsets;       /* ngx_http_charset_t */
    ngx_array_t                 tables;         /* ngx_http_charset_tables_t */
    ngx_array_t                 recodes;        /* ngx_http_charset_recode_t */
} ngx_http_charset_main_conf_t;


typedef struct {
    ngx_int_t                   charset;
    ngx_int_t                   source_charset;
    ngx_flag_t                  override_charset;
} ngx_http_charset_loc_conf_t;


typedef struct {
    u_char                     *table;
    ngx_int_t                   charset;

    ngx_chain_t                *busy;
    ngx_chain_t                *free_bufs;
    ngx_chain_t                *free_buffers;

    size_t                      saved_len;
    u_char                      saved[NGX_UTF_LEN];

    unsigned                    length:16;
    unsigned                    from_utf8:1;
    unsigned                    to_utf8:1;
} ngx_http_charset_ctx_t;


typedef struct {
    ngx_http_charset_tables_t  *table;
    ngx_http_charset_t         *charset;
    ngx_uint_t                  characters;
} ngx_http_charset_conf_ctx_t;


static ngx_int_t ngx_http_charset_get_charset(ngx_http_charset_t *charsets,
    ngx_uint_t n, ngx_str_t *charset);
static ngx_int_t ngx_http_charset_set_charset(ngx_http_request_t *r,
    ngx_http_charset_t *charsets, ngx_int_t charset, ngx_int_t source_charset);
static ngx_uint_t ngx_http_charset_recode(ngx_buf_t *b, u_char *table);
static ngx_chain_t *ngx_http_charset_recode_from_utf8(ngx_pool_t *pool,
    ngx_buf_t *buf, ngx_http_charset_ctx_t *ctx);
static ngx_chain_t *ngx_http_charset_recode_to_utf8(ngx_pool_t *pool,
    ngx_buf_t *buf, ngx_http_charset_ctx_t *ctx);

static ngx_chain_t *ngx_http_charset_get_buf(ngx_pool_t *pool,
    ngx_http_charset_ctx_t *ctx);
static ngx_chain_t *ngx_http_charset_get_buffer(ngx_pool_t *pool,
    ngx_http_charset_ctx_t *ctx, size_t size);

static char *ngx_http_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_charset_map(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);

static char *ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name);

static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_charset_postconfiguration(ngx_conf_t *cf);


static ngx_command_t  ngx_http_charset_filter_commands[] = {

    { ngx_string("charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_charset_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, charset),
      NULL },

    { ngx_string("source_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_charset_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, source_charset),
      NULL },

    { ngx_string("override_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, override_charset),
      NULL },

    { ngx_string("charset_map"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_http_charset_map_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_charset_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_charset_postconfiguration,    /* postconfiguration */

    ngx_http_charset_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_charset_create_loc_conf,      /* create location configuration */
    ngx_http_charset_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_charset_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_charset_filter_module_ctx,   /* module context */
    ngx_http_charset_filter_commands,      /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_charset_header_filter(ngx_http_request_t *r)
{
    u_char                        *ct;
    ngx_int_t                      charset, source_charset;
    ngx_str_t                     *mc, *from, *to, s;
    ngx_uint_t                     n;
    ngx_http_charset_t            *charsets;
    ngx_http_charset_ctx_t        *ctx;
    ngx_http_variable_value_t     *vv;
    ngx_http_charset_loc_conf_t   *lcf, *mlcf;
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);

    charsets = mcf->charsets.elts;
    n = mcf->charsets.nelts;

    /* destination charset */

    if (r == r->main) {

        if (r->headers_out.content_type.len == 0) {
            return ngx_http_next_header_filter(r);
        }

        if (r->headers_out.override_charset
            && r->headers_out.override_charset->len)
        {
            charset = ngx_http_charset_get_charset(charsets, n,
                                              r->headers_out.override_charset);

            if (charset == NGX_HTTP_NO_CHARSET) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unknown charset \"%V\" to override",
                              r->headers_out.override_charset);

                return ngx_http_next_header_filter(r);
            }

        } else {
            mlcf = ngx_http_get_module_loc_conf(r,
                                                ngx_http_charset_filter_module);
            charset = mlcf->charset;

            if (charset == NGX_HTTP_NO_CHARSET) {
                return ngx_http_next_header_filter(r);
            }

            if (r->headers_out.charset.len) {
                if (mlcf->override_charset == 0) {
                    return ngx_http_next_header_filter(r);
                }

            } else {
                ct = r->headers_out.content_type.data;

                if (ngx_strncasecmp(ct, (u_char *) "text/", 5) != 0
                    && ngx_strncasecmp(ct,
                                      (u_char *) "application/x-javascript", 24)
                       != 0)
                {
                    return ngx_http_next_header_filter(r);
                }
            }

            if (charset >= NGX_HTTP_CHARSET_VAR) {
                vv = ngx_http_get_indexed_variable(r,
                                               charset - NGX_HTTP_CHARSET_VAR);

                if (vv == NULL || vv->not_found) {
                    return NGX_ERROR;
                }

                s.len = vv->len;
                s.data = vv->data;

                charset = ngx_http_charset_get_charset(charsets, n, &s);
            }
        }

    } else {
        ctx = ngx_http_get_module_ctx(r->main, ngx_http_charset_filter_module);

        if (ctx == NULL) {

            mc = &r->main->headers_out.charset;

            if (mc->len == 0) {
                return ngx_http_next_header_filter(r);
            }

            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_charset_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }

            ngx_http_set_ctx(r->main, ctx, ngx_http_charset_filter_module);

            charset = ngx_http_charset_get_charset(charsets, n, mc);

            ctx->charset = charset;

        } else {
            charset = ctx->charset;
        }
    }

    /* source charset */

    if (r->headers_out.charset.len == 0) {
        lcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);

        source_charset = lcf->source_charset;

        if (source_charset >= NGX_HTTP_CHARSET_VAR) {
            vv = ngx_http_get_indexed_variable(r,
                                        source_charset - NGX_HTTP_CHARSET_VAR);

            if (vv == NULL || vv->not_found) {
                return NGX_ERROR;
            }

            s.len = vv->len;
            s.data = vv->data;

            source_charset = ngx_http_charset_get_charset(charsets, n, &s);
        }

        if (charset != NGX_HTTP_NO_CHARSET) {
            return ngx_http_charset_set_charset(r, mcf->charsets.elts, charset,
                                                source_charset);
        }

        if (source_charset == NGX_CONF_UNSET) {
            return ngx_http_next_header_filter(r);
        }

        from = &charsets[source_charset].name;
        to = &r->main->headers_out.charset;

        goto no_charset_map;
    }

    source_charset = ngx_http_charset_get_charset(charsets, n,
                                                  &r->headers_out.charset);

    if (charset == NGX_HTTP_NO_CHARSET
        || source_charset == NGX_HTTP_NO_CHARSET)
    {
        if (charset != source_charset
            || ngx_strcasecmp(r->main->headers_out.charset.data,
                              r->headers_out.charset.data)
                != 0)
        {
            from = &r->headers_out.charset;
            to = (charset == NGX_HTTP_NO_CHARSET) ?
                                           &r->main->headers_out.charset:
                                           &charsets[charset].name;

            goto no_charset_map;
        }

        return ngx_http_next_header_filter(r);
    }

    if (source_charset != charset
        && (charsets[source_charset].tables == NULL
            || charsets[source_charset].tables[charset] == NULL))
    {
        from = &charsets[source_charset].name;
        to = &charsets[charset].name;

        goto no_charset_map;
    }

    r->headers_out.content_type.len = r->headers_out.content_type_len;

    return ngx_http_charset_set_charset(r, mcf->charsets.elts, charset,
                                        source_charset);

no_charset_map:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                  from, to);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_charset_get_charset(ngx_http_charset_t *charsets, ngx_uint_t n,
    ngx_str_t *charset)
{
    ngx_uint_t  i;

    for (i = 0; i < n; i++) {
        if (charsets[i].name.len != charset->len) {
            continue;
        }

        if (ngx_strncasecmp(charsets[i].name.data, charset->data, charset->len)
            == 0)
        {
            return i;
        }
    }

    return NGX_HTTP_NO_CHARSET;
}


static ngx_int_t
ngx_http_charset_set_charset(ngx_http_request_t *r,
    ngx_http_charset_t *charsets, ngx_int_t charset, ngx_int_t source_charset)
{
    ngx_http_charset_ctx_t  *ctx;

    if (r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY
        || r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY)
    {
        /*
         * do not set charset for the redirect because NN 4.x
         * use this charset instead of the next page charset
         */

        r->headers_out.charset.len = 0;

        return ngx_http_next_header_filter(r);
    }

    r->headers_out.charset = charsets[charset].name;
    r->utf8 = charsets[charset].utf8;

    if (source_charset == NGX_CONF_UNSET || source_charset == charset) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_charset_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_charset_filter_module);

    ctx->table = charsets[source_charset].tables[charset];
    ctx->charset = charset;
    ctx->length = charsets[charset].length;
    ctx->from_utf8 = charsets[source_charset].utf8;
    ctx->to_utf8 = charsets[charset].utf8;

    r->filter_need_in_memory = 1;

    if ((ctx->to_utf8 || ctx->from_utf8) && r == r->main) {
        ngx_http_clear_content_length(r);

    } else {
        r->filter_need_temporary = 1;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_charset_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                rc;
    ngx_buf_t               *b;
    ngx_chain_t             *cl, *out, **ll;
    ngx_http_charset_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_charset_filter_module);

    if (ctx == NULL || ctx->table == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if ((ctx->to_utf8 || ctx->from_utf8) || ctx->busy) {

        out = NULL;
        ll = &out;

        for (cl = in; cl; cl = cl->next) {
            b = cl->buf;

            if (ngx_buf_size(b) == 0) {

                *ll = ngx_alloc_chain_link(r->pool);
                if (*ll == NULL) {
                    return NGX_ERROR;
                }

                (*ll)->buf = b;
                (*ll)->next = NULL;

                ll = &(*ll)->next;

                continue;
            }

            if (ctx->to_utf8) {
                *ll = ngx_http_charset_recode_to_utf8(r->pool, b, ctx);

            } else {
                *ll = ngx_http_charset_recode_from_utf8(r->pool, b, ctx);
            }

            if (*ll == NULL) {
                return NGX_ERROR;
            }

            while (*ll) {
                ll = &(*ll)->next;
            }
        }

        rc = ngx_http_next_body_filter(r, out);

        if (out) {
            if (ctx->busy == NULL) {
                ctx->busy = out;

            } else {
                for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
                cl->next = out;
            }
        }

        while (ctx->busy) {

            cl = ctx->busy;
            b = cl->buf;

            if (ngx_buf_size(b) != 0) {
                break;
            }

#if (NGX_HAVE_WRITE_ZEROCOPY)
            if (b->zerocopy_busy) {
                break;
            }
#endif

            ctx->busy = cl->next;

            if (b->tag != (ngx_buf_tag_t) &ngx_http_charset_filter_module) {
                continue;
            }

            if (b->shadow) {
                b->shadow->pos = b->shadow->last;
            }

            if (b->pos) {
                cl->next = ctx->free_buffers;
                ctx->free_buffers = cl;
                continue;
            }

            cl->next = ctx->free_bufs;
            ctx->free_bufs = cl;
        }

        return rc;
    }

    for (cl = in; cl; cl = cl->next) {
        (void) ngx_http_charset_recode(cl->buf, ctx->table);
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_uint_t
ngx_http_charset_recode(ngx_buf_t *b, u_char *table)
{
    u_char  *p;

    for (p = b->pos; p < b->last; p++) {

        if (*p == table[*p]) {
            continue;
        }

        while (p < b->last) {
            *p = table[*p];
            p++;
        }

        b->in_file = 0;

        return 1;
    }

    return 0;
}


static ngx_chain_t *
ngx_http_charset_recode_from_utf8(ngx_pool_t *pool, ngx_buf_t *buf,
    ngx_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char        c, *p, *src, *dst, *saved, **table;
    uint32_t      n;
    ngx_buf_t    *b;
    ngx_uint_t    i;
    ngx_chain_t  *out, *cl, **ll;

    src = buf->pos;

    if (ctx->saved_len == 0) {

        for ( /* void */ ; src < buf->last; src++) {

            if (*src < 0x80) {
                continue;
            }

            len = src - buf->pos;

            if (len > 512) {
                out = ngx_http_charset_get_buf(pool, ctx);
                if (out == NULL) {
                    return NULL;
                }

                b = out->buf;

                b->temporary = buf->temporary;
                b->memory = buf->memory;
                b->mmap = buf->mmap;
                b->flush = buf->flush;

                b->pos = buf->pos;
                b->last = src;

                out->buf = b;
                out->next = NULL;

                size = buf->last - src;

                saved = src;
                n = ngx_utf_decode(&saved, size);

                if (n == 0xfffffffe) {
                    /* incomplete UTF-8 symbol */

                    ngx_memcpy(ctx->saved, src, size);
                    ctx->saved_len = size;

                    b->shadow = buf;

                    return out;
                }

            } else {
                out = NULL;
                size = len + buf->last - src;
                src = buf->pos;
            }

            if (size < NGX_HTML_ENTITY_LEN) {
                size += NGX_HTML_ENTITY_LEN;
            }

            cl = ngx_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            if (out) {
                out->next = cl;

            } else {
                out = cl;
            }

            b = cl->buf;
            dst = b->pos;

            goto recode;
        }

        out = ngx_alloc_chain_link(pool);
        if (out == NULL) {
            return NULL;
        }

        out->buf = buf;
        out->next = NULL;

        return out;
    }

    /* process incomplete UTF sequence from previous buffer */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "http charset utf saved: %z", ctx->saved_len);

    p = src;

    for (i = ctx->saved_len; i < NGX_UTF_LEN; i++) {
        ctx->saved[i] = *p++;

        if (p == buf->last) {
            break;
        }
    }

    saved = ctx->saved;
    n = ngx_utf_decode(&saved, i);

    c = '\0';

    if (n < 0x10000) {
        table = (u_char **) ctx->table;
        p = table[n >> 8];

        if (p) {
            c = p[n & 0xff];
        }

    } else if (n == 0xfffffffe) {

        /* incomplete UTF-8 symbol */

        if (i < NGX_UTF_LEN) {
            out = ngx_http_charset_get_buf(pool, ctx);
            if (out == NULL) {
                return NULL;
            }

            b = out->buf;

            b->pos = buf->pos;
            b->last = buf->last;
            b->sync = 1;
            b->shadow = buf;

            ngx_memcpy(&ctx->saved[ctx->saved_len], src, i);
            ctx->saved_len += i;

            return out;
        }
    }

    size = buf->last - buf->pos;

    if (size < NGX_HTML_ENTITY_LEN) {
        size += NGX_HTML_ENTITY_LEN;
    }

    cl = ngx_http_charset_get_buffer(pool, ctx, size);
    if (cl == NULL) {
        return NULL;
    }

    out = cl;

    b = cl->buf;
    dst = b->pos;

    if (c) {
        *dst++ = c;

    } else if (n == 0xfffffffe) {
        *dst++ = '?';

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 0");

        saved = &ctx->saved[NGX_UTF_LEN];

    } else if (n > 0x10ffff) {
        *dst++ = '?';

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 1");

    } else {
        dst = ngx_sprintf(dst, "&#%uD;", n);
    }

    src += (saved - ctx->saved) - ctx->saved_len;
    ctx->saved_len = 0;

recode:

    ll = &cl->next;

    table = (u_char **) ctx->table;

    while (src < buf->last) {

        if ((size_t) (b->end - dst) < NGX_HTML_ENTITY_LEN) {
            b->last = dst;

            size = buf->last - src + NGX_HTML_ENTITY_LEN;

            cl = ngx_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            dst = b->pos;
        }

        if (*src < 0x80) {
            *dst++ = *src++;
            continue;
        }

        len = buf->last - src;

        n = ngx_utf_decode(&src, len);

        if (n < 0x10000) {

            p = table[n >> 8];

            if (p) {
                c = p[n & 0xff];

                if (c) {
                    *dst++ = c;
                    continue;
                }
            }

            dst = ngx_sprintf(dst, "&#%uD;", n);

            continue;
        }

        if (n == 0xfffffffe) {
            /* incomplete UTF-8 symbol */

            ngx_memcpy(ctx->saved, src, len);
            ctx->saved_len = len;

            if (b->pos == dst) {
                b->sync = 1;
                b->temporary = 0;
            }

            break;
        }

        if (n > 0x10ffff) {
            *dst++ = '?';

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                           "http charset invalid utf 2");

            continue;
        }

        /* n > 0xffff */

        dst = ngx_sprintf(dst, "&#%uD;", n);
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static ngx_chain_t *
ngx_http_charset_recode_to_utf8(ngx_pool_t *pool, ngx_buf_t *buf,
    ngx_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char       *p, *src, *dst, *table;
    ngx_buf_t    *b;
    ngx_chain_t  *out, *cl, **ll;

    table = ctx->table;

    for (src = buf->pos; src < buf->last; src++) {
        if (table[*src * NGX_UTF_LEN] == '\1') {
            continue;
        }

        goto recode;
    }

    out = ngx_alloc_chain_link(pool);
    if (out == NULL) {
        return NULL;
    }

    out->buf = buf;
    out->next = NULL;

    return out;

recode:

    /*
     * we assume that there are about half of characters to be recoded,
     * so we preallocate "size / 2 + size / 2 * ctx->length"
     */

    len = src - buf->pos;

    if (len > 512) {
        out = ngx_http_charset_get_buf(pool, ctx);
        if (out == NULL) {
            return NULL;
        }

        b = out->buf;

        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->flush = buf->flush;

        b->pos = buf->pos;
        b->last = src;

        out->buf = b;
        out->next = NULL;

        size = buf->last - src;
        size = size / 2 + size / 2 * ctx->length;

    } else {
        out = NULL;

        size = buf->last - src;
        size = len + size / 2 + size / 2 * ctx->length;

        src = buf->pos;
    }

    cl = ngx_http_charset_get_buffer(pool, ctx, size);
    if (cl == NULL) {
        return NULL;
    }

    if (out) {
        out->next = cl;

    } else {
        out = cl;
    }

    ll = &cl->next;

    b = cl->buf;
    dst = b->pos;

    while (src < buf->last) {

        p = &table[*src++ * NGX_UTF_LEN];
        len = *p++;

        if ((size_t) (b->end - dst) < len) {
            b->last = dst;

            size = buf->last - src;
            size = len + size / 2 + size / 2 * ctx->length;

            cl = ngx_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            dst = b->pos;
        }

        while (len) {
            *dst++ = *p++;
            len--;
        }
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static ngx_chain_t *
ngx_http_charset_get_buf(ngx_pool_t *pool, ngx_http_charset_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    cl = ctx->free_bufs;

    if (cl) {
        ctx->free_bufs = cl->next;

        cl->buf->shadow = NULL;
        cl->next = NULL;

        return cl;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(pool);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->tag = (ngx_buf_tag_t) &ngx_http_charset_filter_module;

    return cl;
}


static ngx_chain_t *
ngx_http_charset_get_buffer(ngx_pool_t *pool, ngx_http_charset_ctx_t *ctx,
    size_t size)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl, **ll;

    for (ll = &ctx->free_buffers, cl = ctx->free_buffers;
         cl;
         ll = &cl->next, cl = cl->next)
    {
        b = cl->buf;

        if ((size_t) (b->end - b->start) >= size) {
            *ll = cl->next;
            cl->next = NULL;

            b->pos = b->start;
            b->temporary = 1;
            b->shadow = NULL;

            return cl;
        }
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_create_temp_buf(pool, size);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->temporary = 1;
    cl->buf->tag = (ngx_buf_tag_t) &ngx_http_charset_filter_module;

    return cl;
}


static char *
ngx_http_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_charset_main_conf_t  *mcf = conf;

    char                         *rv;
    u_char                       *p, *dst2src, **pp;
    ngx_int_t                     src, dst;
    ngx_uint_t                    i, n;
    ngx_str_t                    *value;
    ngx_conf_t                    pvcf;
    ngx_http_charset_t           *charset;
    ngx_http_charset_tables_t    *table;
    ngx_http_charset_conf_ctx_t   ctx;

    value = cf->args->elts;

    src = ngx_http_add_charset(&mcf->charsets, &value[1]);
    if (src == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    dst = ngx_http_add_charset(&mcf->charsets, &value[2]);
    if (dst == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (src == dst) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"charset_map\" between the same charsets "
                           "\"%V\" and \"%V\"", &value[1], &value[2]);
        return NGX_CONF_ERROR;
    }

    table = mcf->tables.elts;
    for (i = 0; i < mcf->tables.nelts; i++) {
        if ((src == table->src && dst == table->dst)
             || (src == table->dst && dst == table->src))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"charset_map\" between "
                               "\"%V\" and \"%V\"", &value[1], &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    table = ngx_array_push(&mcf->tables);
    if (table == NULL) {
        return NGX_CONF_ERROR;
    }

    table->src = src;
    table->dst = dst;

    if (ngx_strcasecmp(value[2].data, (u_char *) "utf-8") == 0) {
        table->src2dst = ngx_pcalloc(cf->pool, 256 * NGX_UTF_LEN);
        if (table->src2dst == NULL) {
            return NGX_CONF_ERROR;
        }

        table->dst2src = ngx_pcalloc(cf->pool, 256 * sizeof(void *));
        if (table->dst2src == NULL) {
            return NGX_CONF_ERROR;
        }

        dst2src = ngx_pcalloc(cf->pool, 256);
        if (dst2src == NULL) {
            return NGX_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];
        pp[0] = dst2src;

        for (i = 0; i < 128; i++) {
            p = &table->src2dst[i * NGX_UTF_LEN];
            p[0] = '\1';
            p[1] = (u_char) i;
            dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            p = &table->src2dst[i * NGX_UTF_LEN];
            p[0] = '\1';
            p[1] = '?';
        }

    } else {
        table->src2dst = ngx_palloc(cf->pool, 256);
        if (table->src2dst == NULL) {
            return NGX_CONF_ERROR;
        }

        table->dst2src = ngx_palloc(cf->pool, 256);
        if (table->dst2src == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < 128; i++) {
            table->src2dst[i] = (u_char) i;
            table->dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            table->src2dst[i] = '?';
            table->dst2src[i] = '?';
        }
    }

    charset = mcf->charsets.elts;

    ctx.table = table;
    ctx.charset = &charset[dst];
    ctx.characters = 0;

    pvcf = *cf;
    cf->ctx = &ctx;
    cf->handler = ngx_http_charset_map;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pvcf;

    if (ctx.characters) {
        n = ctx.charset->length;
        ctx.charset->length /= ctx.characters;

        if (((n * 10) / ctx.characters) % 10 > 4) {
            ctx.charset->length++;
        }
    }

    return rv;
}


static char *
ngx_http_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    u_char                       *p, *dst2src, **pp;
    uint32_t                      n;
    ngx_int_t                     src, dst;
    ngx_str_t                    *value;
    ngx_uint_t                    i;
    ngx_http_charset_tables_t    *table;
    ngx_http_charset_conf_ctx_t  *ctx;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameters number");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    src = ngx_hextoi(value[0].data, value[0].len);
    if (src == NGX_ERROR || src > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }

    ctx = cf->ctx;
    table = ctx->table;

    if (ctx->charset->utf8) {
        p = &table->src2dst[src * NGX_UTF_LEN];

        *p++ = (u_char) (value[1].len / 2);

        for (i = 0; i < value[1].len; i += 2) {
            dst = ngx_hextoi(&value[1].data[i], 2);
            if (dst == NGX_ERROR || dst > 255) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[1]);
                return NGX_CONF_ERROR;
            }

            *p++ = (u_char) dst;
        }

        i /= 2;

        ctx->charset->length += i;
        ctx->characters++;

        p = &table->src2dst[src * NGX_UTF_LEN] + 1;

        n = ngx_utf_decode(&p, i);

        if (n > 0xffff) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];

        dst2src = pp[n >> 8];

        if (dst2src == NULL) {
            dst2src = ngx_pcalloc(cf->pool, 256);
            if (dst2src == NULL) {
                return NGX_CONF_ERROR;
            }

            pp[n >> 8] = dst2src;
        }

        dst2src[n & 0xff] = (u_char) src;

    } else {
        dst = ngx_hextoi(value[1].data, value[1].len);
        if (dst == NGX_ERROR || dst > 255) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        table->src2dst[src] = (u_char) dst;
        table->dst2src[dst] = (u_char) src;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t                     *cp;
    ngx_str_t                     *value, var;
    ngx_http_charset_main_conf_t  *mcf;

    cp = (ngx_int_t *) (p + cmd->offset);

    if (*cp != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cmd->offset == offsetof(ngx_http_charset_loc_conf_t, charset)
        && ngx_strcmp(value[1].data, "off") == 0)
    {
        *cp = NGX_HTTP_NO_CHARSET;
        return NGX_CONF_OK;
    }


    if (value[1].data[0] == '$') {
        var.len = value[1].len - 1;
        var.data = value[1].data + 1;

        *cp = ngx_http_get_variable_index(cf, &var);

        if (*cp == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        *cp += NGX_HTTP_CHARSET_VAR;

        return NGX_CONF_OK;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);

    *cp = ngx_http_add_charset(&mcf->charsets, &value[1]);
    if (*cp == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name)
{
    ngx_uint_t           i;
    ngx_http_charset_t  *c;

    c = charsets->elts;
    for (i = 0; i < charsets->nelts; i++) {
        if (name->len != c[i].name.len) {
            continue;
        }

        if (ngx_strcasecmp(name->data, c[i].name.data) == 0) {
            break;
        }
    }

    if (i < charsets->nelts) {
        return i;
    }

    c = ngx_array_push(charsets);
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->tables = NULL;
    c->name = *name;
    c->length = 0;

    if (ngx_strcasecmp(name->data, (u_char *) "utf-8") == 0) {
        c->utf8 = 1;

    } else {
        c->utf8 = 0;
    }

    return i;
}


static void *
ngx_http_charset_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_main_conf_t));
    if (mcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&mcf->charsets, cf->pool, 2, sizeof(ngx_http_charset_t))
        == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&mcf->tables, cf->pool, 1,
                       sizeof(ngx_http_charset_tables_t)) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&mcf->recodes, cf->pool, 2,
                       sizeof(ngx_http_charset_recode_t)) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return mcf;
}


static void *
ngx_http_charset_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_charset_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_loc_conf_t));
    if (lcf == NULL) {
        return NGX_CONF_ERROR;
    }

    lcf->charset = NGX_CONF_UNSET;
    lcf->source_charset = NGX_CONF_UNSET;
    lcf->override_charset = NGX_CONF_UNSET;

    return lcf;
}


static char *
ngx_http_charset_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_charset_loc_conf_t *prev = parent;
    ngx_http_charset_loc_conf_t *conf = child;

    ngx_uint_t                     i;
    ngx_http_charset_recode_t     *recode;
    ngx_http_charset_main_conf_t  *mcf;

    ngx_conf_merge_value(conf->override_charset, prev->override_charset, 0);
    ngx_conf_merge_value(conf->charset, prev->charset, NGX_HTTP_NO_CHARSET);

    if (conf->source_charset == NGX_CONF_UNSET) {
        conf->source_charset = prev->source_charset;
    }

    if (conf->charset == NGX_HTTP_NO_CHARSET
        || conf->source_charset == NGX_CONF_UNSET
        || conf->charset == conf->source_charset)
    {
        return NGX_CONF_OK;
    }

    if (conf->source_charset >= NGX_HTTP_CHARSET_VAR
        || conf->charset >= NGX_HTTP_CHARSET_VAR)
    {
        return NGX_CONF_OK;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);
    recode = mcf->recodes.elts;
    for (i = 0; i < mcf->recodes.nelts; i++) {
        if (conf->source_charset == recode[i].src
            && conf->charset == recode[i].dst)
        {
            return NGX_CONF_OK;
        }
    }

    recode = ngx_array_push(&mcf->recodes);
    if (recode == NULL) {
        return NGX_CONF_ERROR;
    }

    recode->src = conf->source_charset;
    recode->dst = conf->charset;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_charset_postconfiguration(ngx_conf_t *cf)
{
    u_char                       **src, **dst;
    ngx_int_t                      c;
    ngx_uint_t                     i, t;
    ngx_http_charset_t            *charset;
    ngx_http_charset_recode_t     *recode;
    ngx_http_charset_tables_t     *tables;
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);

    recode = mcf->recodes.elts;
    tables = mcf->tables.elts;
    charset = mcf->charsets.elts;

    for (i = 0; i < mcf->recodes.nelts; i++) {

        c = recode[i].src;

        for (t = 0; t < mcf->tables.nelts; t++) {

            if (c == tables[t].src && recode[i].dst == tables[t].dst) {
                goto next;
            }

            if (c == tables[t].dst && recode[i].dst == tables[t].src) {
                goto next;
            }
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                   "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                   &charset[c].name, &charset[recode[i].dst].name);
        return NGX_ERROR;

    next:
        continue;
    }


    for (t = 0; t < mcf->tables.nelts; t++) {

        src = charset[tables[t].src].tables;

        if (src == NULL) {
            src = ngx_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (src == NULL) {
                return NGX_ERROR;
            }

            charset[tables[t].src].tables = src;
        }

        dst = charset[tables[t].dst].tables;

        if (dst == NULL) {
            dst = ngx_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (dst == NULL) {
                return NGX_ERROR;
            }

            charset[tables[t].dst].tables = dst;
        }

        src[tables[t].dst] = tables[t].src2dst;
        dst[tables[t].src] = tables[t].dst2src;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_charset_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_charset_body_filter;

    return NGX_OK;
}
