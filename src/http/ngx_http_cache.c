
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <md5.h>

/* STUB */
#if (WIN32)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif


int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx)
{
    MD5_CTX  md5;

    ctx->header_size = sizeof(ngx_http_cache_header_t) + ctx->key.len + 1;

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

    return ngx_http_cache_open_file(r, ctx, 0);
}


/* TODO: Win32 inode analogy */

int ngx_http_cache_open_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx,
                             ngx_file_uniq_t uniq)
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

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", ctx->file.name.data);
        return NGX_ERROR;
    }

    if (uniq) {
        if (ngx_stat_fd(ctx->file.fd, &ctx->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_stat_fd_n " \"%s\" failed", ctx->file.name.data);

            return NGX_ERROR;
        }

        if (ngx_file_uniq((&ctx->file.info)) == uniq) {
            if (ngx_close_file(ctx->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
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
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" is too small", ctx->file.name.data);
        return NGX_ERROR;
    }

    h = (ngx_http_cache_header_t *) ctx->buf->pos;
    ctx->expires = h->expires;
    ctx->last_modified= h->last_modified;
    ctx->date = h->date;
    ctx->length = h->length;

    if (h->key_len != ctx->key.len
        || ngx_strncmp(h->key, ctx->key.data, h->key_len) != 0)
    {
        h->key[h->key_len] = '\0';
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "md5 collision: \"%s\" and \"%s\"",
                          h->key, ctx->key.data);
        return NGX_DECLINED;
    }

    ctx->buf->last += n;

    if (ctx->expires < ngx_time()) {
ngx_log_debug(r->connection->log, "EXPIRED");
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
        if (ngx_rename_file(temp_file, (&ctx->file.name), r->pool) == NGX_OK) {
            return NGX_OK;
        }

        err = ngx_errno;

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


#if 0

/*
 * small file in malloc()ed memory, mmap()ed file, file descriptor only,
 * file access time only (to estimate could pages still be in memory),
 * translated URI (ngx_http_index_hanlder),
 * compiled script (ngx_http_ssi_filter).
 */


#define NGX_HTTP_CACHE_ENTRY_DELETED  0x00000001
#define NGX_HTTP_CACHE_ENTRY_MMAPED   0x00000002

/* "/" -> "/index.html" in ngx_http_index_handler */
#define NGX_HTTP_CACHE_ENTRY_URI      0x00000004

/* 301 location "/dir" -> "dir/" in ngx_http_core_handler */

/* compiled script in ngx_http_ssi_filter  */
#define NGX_HTTP_CACHE_ENTRY_SCRIPT   0x00000008

#define NGX_HTTP_CACHE_FILTER_FLAGS   0xFFFF0000


typedef struct {
    ngx_fd_t   fd;
    off_t      size;
    void      *data;
    time_t     accessed;
    time_t     last_modified;
    time_t     updated;      /* no needed with kqueue */
    int        refs;
    int        flags;
} ngx_http_cache_entry_t;


typedef struct {
    u_int32_t          crc;
    ngx_str_t          uri;
    ngx_http_cache_t  *cache;
} ngx_http_cache_hash_entry_t;


typedef struct {
    ngx_http_cache_t  *cache;
    u_int32_t          crc;
    int                n;
} ngx_http_cache_handle_t; 


int ngx_http_cache_get(ngx_http_cache_hash_t *cache_hash,
                       ngx_str_t *uri, ngx_http_cache_handle_t *h)
{
    int                           hi;
    ngx_http_cache_hash_entry_t  *entry;

    h->crc = ngx_crc(uri->data, uri->len);

    hi = h->crc % cache_hash->size;
    entry = cache_hash[hi].elts;

    for (i = 0; i < cache_hash[hi].nelts; i++) {
        if (entry[i].crc == crc
            && entry[i].uri.len == uri->len
            && ngx_strncmp(entry[i].uri.data, uri->data, uri->len) == 0
        {
            h->cache = entry[i].cache;
            h->cache->refs++;
            h->n = hi;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


/* 32-bit crc16 */

int ngx_crc(char *data, size_t len)
{
    u_int32_t  sum;

    for (sum = 0; len; len--) {
        /*
         * gcc 2.95.2 x86 and icc 7.1.006 compile that operator
         * into the single rol opcode.
         * msvc 6.0sp2 compiles it into four opcodes.
         */
        sum = sum >> 1 | sum << 31;

        sum += *data++;
    }

    return sum;
}

#endif
