
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <md5.h>

#if (HAVE_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif


static int ngx_crc(char *data, size_t len);

static void *ngx_http_cache_create_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child);


static ngx_http_module_t  ngx_http_cache_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cache_create_conf,            /* create location configuration */
    ngx_http_core_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_cache_module = {
    NGX_MODULE,
    &ngx_http_cache_module_ctx,            /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};



int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx)
{
    MD5_CTX  md5;

    /* we use offsetof() because sizeof() pads struct size to int size */
    ctx->header_size = offsetof(ngx_http_cache_header_t, key)
                                                            + ctx->key.len + 1;

    ctx->file.name.len = ctx->path->name.len + 1 + ctx->path->len + 32;
    if (!(ctx->file.name.data = ngx_palloc(r->pool, ctx->file.name.len + 1))) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->file.name.data, ctx->path->name.data, ctx->path->name.len);

    MD5Init(&md5);
    MD5Update(&md5, (u_char *) ctx->key.data, ctx->key.len);
    MD5Final(ctx->md5, &md5);

    ngx_md5_text(ctx->file.name.data + ctx->path->name.len + 1 + ctx->path->len,
                 ctx->md5);

ngx_log_debug(r->connection->log, "URL: %s, md5: %s" _ ctx->key.data _
              ctx->file.name.data + ctx->path->name.len + 1 + ctx->path->len);

    ngx_create_hashed_filename(&ctx->file, ctx->path);

ngx_log_debug(r->connection->log, "FILE: %s" _ ctx->file.name.data);

    /* TODO: look open files cache */

    return ngx_http_cache_open_file(ctx, 0);
}


ngx_http_cache_t *ngx_http_cache_get(ngx_http_cache_hash_t *cache,
                                     ngx_str_t *key, uint32_t *crc)
{
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    *crc = ngx_crc(key->data, key->len);

    c = cache->elts
                + *crc % cache->hash * cache->nelts * sizeof(ngx_http_cache_t);

    for (i = 0; i < cache->nelts; i++) {
        if (c[i].crc == *crc
            && c[i].key.len == key->len
            && ngx_rstrncmp(c[i].key.data, key->data, key->len) == 0)
        {
            c[i].refs++;
            return &c[i];
        }
    }

    return NULL;
}


ngx_http_cache_t *ngx_http_cache_alloc(ngx_http_cache_hash_t *cache,
                                       ngx_str_t *key, uint32_t crc,
                                       ngx_log_t *log)
{
    time_t             old;
    ngx_uint_t         i;
    ngx_http_cache_t  *c, *found;

    old = ngx_time() + 1;
    found = NULL;

    c = cache->elts
                 + crc % cache->hash * cache->nelts * sizeof(ngx_http_cache_t);

    for (i = 0; i < cache->nelts; i++) {
        if (c[i].key.data == NULL) {

            /* a free entry is found */

            found = &c[i];
            break;
        }

        /* looking for the oldest cache entry that is not been using */

        if (c[i].refs == 0 && old > c[i].accessed) {

            old = c[i].accessed;
            found = &c[i];
        }
    }

    if (found) {
        if (found->key.data) {
            if (key->len > found->key.len) {
                ngx_free(found->key.data);
                found->key.data = NULL;
            }
        }

        if (found->key.data == NULL) {
            found->key.data = ngx_alloc(key->len, log);
            if (found->key.data == NULL) {
                return NULL;
            }
        }

        ngx_memcpy(found->key.data, key->data, key->len);

        found->crc = crc;
        found->key.len = key->len;
        found->refs = 1;
        found->deleted = 0;
    }

    return found;
}


int ngx_http_cache_open_file(ngx_http_cache_ctx_t *ctx, ngx_file_uniq_t uniq)
{
    ssize_t                   n;
    ngx_err_t                 err;
    ngx_http_cache_header_t  *h;

    ctx->file.fd = ngx_open_file(ctx->file.name.data,
                                 NGX_FILE_RDONLY, NGX_FILE_OPEN);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
            return NGX_DECLINED;
        }

        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", ctx->file.name.data);
        return NGX_ERROR;
    }

    if (uniq) {
        if (ngx_fd_info(ctx->file.fd, &ctx->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", ctx->file.name.data);

            return NGX_ERROR;
        }

        if (ngx_file_uniq(&ctx->file.info) == uniq) {
            if (ngx_close_file(ctx->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              ctx->file.name.data);
            }

            return NGX_HTTP_CACHE_THE_SAME;
        }
    }

    n = ngx_read_file(&ctx->file, ctx->buf->pos,
                      ctx->buf->end - ctx->buf->last, 0);

    if (n == NGX_ERROR || n == NGX_AGAIN) {
        return n;
    }

    if (n <= ctx->header_size) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, 0,
                      "cache file \"%s\" is too small", ctx->file.name.data);
        return NGX_ERROR;
    }

    h = (ngx_http_cache_header_t *) ctx->buf->pos;
    ctx->expires = h->expires;
    ctx->last_modified= h->last_modified;
    ctx->date = h->date;
    ctx->length = h->length;

    if (h->key_len > (size_t) (ctx->buf->end - ctx->buf->pos)) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                      "cache file \"%s\" is probably invalid",
                      ctx->file.name.data);
        return NGX_DECLINED;
    }

    if (ctx->key.len
        && (h->key_len != ctx->key.len
            || ngx_strncmp(h->key, ctx->key.data, h->key_len) != 0))
    {
        h->key[h->key_len] = '\0';
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                          "md5 collision: \"%s\" and \"%s\"",
                          h->key, ctx->key.data);
        return NGX_DECLINED;
    }

    ctx->buf->last += n;

    if (ctx->expires < ngx_time()) {
ngx_log_debug(ctx->log, "EXPIRED");
        return NGX_HTTP_CACHE_STALE;
    }

    /* TODO: NGX_HTTP_CACHE_AGED */

    return NGX_OK;
}


int ngx_http_cache_update_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx,
                               ngx_str_t *temp_file)
{
    int        retry;
    ngx_err_t  err;

    retry = 0;

    for ( ;; ) {
        if (ngx_rename_file(temp_file->data, ctx->file.name.data) == NGX_OK) {
            return NGX_OK;
        }

        err = ngx_errno;

#if (WIN32)
        if (err == NGX_EEXIST) {
            if (ngx_win32_rename_file(temp_file, &ctx->file.name, r->pool)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
#endif

        if (retry || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_rename_file_n "(\"%s\", \"%s\") failed",
                          temp_file->data, ctx->file.name.data);

            return NGX_ERROR;
        }

        if (ngx_create_path(&ctx->file, ctx->path) == NGX_ERROR) {
            return NGX_ERROR;
        }

        retry = 1;
    }
}


int ngx_garbage_collector_http_cache_handler(ngx_gc_t *gc, ngx_str_t *name,
                                             ngx_dir_t *dir)
{
    int                   rc;
    char                  data[sizeof(ngx_http_cache_header_t)];
    ngx_hunk_t            buf;
    ngx_http_cache_ctx_t  ctx;

    ctx.file.fd = NGX_INVALID_FILE;
    ctx.file.name = *name;
    ctx.file.log = gc->log;

    ctx.header_size = sizeof(ngx_http_cache_header_t);
    ctx.buf = &buf;
    ctx.log = gc->log;
    ctx.key.len = 0;

    buf.type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
    buf.pos = data;
    buf.last = data;
    buf.start = data;
    buf.end = data + sizeof(ngx_http_cache_header_t);

    rc = ngx_http_cache_open_file(&ctx, 0);

    /* TODO: NGX_AGAIN */

    if (rc != NGX_ERROR && rc != NGX_DECLINED && rc != NGX_HTTP_CACHE_STALE) {
        return NGX_OK;
    }

    if (ngx_delete_file(name->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, gc->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name->data);
        return NGX_ERROR;
    }

    gc->deleted++;
    gc->freed += ngx_de_size(dir);

    return NGX_OK;
}


/* 32-bit crc16 */

static int ngx_crc(char *data, size_t len)
{
    uint32_t  sum;

    for (sum = 0; len; len--) {
        /*
         * gcc 2.95.2 x86 and icc 7.1.006 compile that operator
         *                                into the single rol opcode.
         * msvc 6.0sp2 compiles it into four opcodes.
         */
        sum = sum >> 1 | sum << 31;

        sum += *data++;
    }

    return sum;
}


static void *ngx_http_cache_create_conf(ngx_conf_t *cf)
{
    ngx_http_cache_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child)
{
    ngx_http_cache_conf_t *prev = parent;
    ngx_http_cache_conf_t *conf = child;

    if (conf->open_files == NULL) {
        if (prev->open_files) {
            conf->open_files = prev->open_files;

        } else {
            conf->open_files = ngx_pcalloc(cf->pool,
                                           sizeof(ngx_http_cache_hash_t));
            if (conf->open_files == NULL) {
                return NGX_CONF_ERROR;
            }

            conf->open_files->hash = NGX_HTTP_CACHE_HASH;
            conf->open_files->nelts = NGX_HTTP_CACHE_NELTS;

            conf->open_files->elts = ngx_pcalloc(cf->pool,
                                                 NGX_HTTP_CACHE_HASH
                                                 * NGX_HTTP_CACHE_NELTS
                                                 * sizeof(ngx_http_cache_t));
            if (conf->open_files->elts == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}
