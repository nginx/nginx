
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <md5.h>


int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx)
{
    int                    small;
    ssize_t                n, len;
    MD5_CTX                md5;
    ngx_err_t              err;
    ngx_str_t              key;
    ngx_http_bin_cache_t  *h;

    ctx->file.name.len = ctx->path->name.len + 1 + ctx->path->len + 32;
    if (!(ctx->file.name.data = ngx_palloc(r->pool, ctx->file.name.len + 1))) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->file.name.data, ctx->path->name.data, ctx->path->name.len);

    MD5Init(&md5);
    MD5Update(&md5, (u_char *) ctx->key.data, ctx->key.len);
    MD5End(&md5,
           ctx->file.name.data + ctx->path->name.len + 1 + ctx->path->len);

ngx_log_debug(r->connection->log, "URL: %s, md5: %s" _ ctx->key.data _
              ctx->file.name.data + ctx->path->name.len + 1 + ctx->path->len);

    ngx_create_hashed_filename(&ctx->file, ctx->path);

ngx_log_debug(r->connection->log, "FILE: %s" _ ctx->file.name.data);

    /* TODO: look open files cache */

    ctx->file.fd = ngx_open_file(ctx->file.name.data,
                                 NGX_FILE_RDONLY, NGX_FILE_OPEN);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {

            /* TODO: text size */

            ctx->header.size = 2 * sizeof(ssize_t)
                               + sizeof(ngx_http_cache_header_t)
                               + ctx->key.len + 1;

            return NGX_DECLINED;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", ctx->file.name.data);
        return NGX_ERROR;
    }

    n = ngx_read_file(&ctx->file, ctx->buf->pos,
                      ctx->buf->end - ctx->buf->last, 0);

    if (n == NGX_ERROR || n == NGX_AGAIN) {
        return n;
    }

    len = 0;
    small = 1;

    if (n > 1) {
        if (ctx->buf->pos[0] == 'T') {
            /* STUB */
            return NGX_ERROR;

        } else if (ctx->buf->pos[0] == 'B') {

            len = sizeof(ngx_http_bin_cache_t);

            if (n > len) {
                h = (ngx_http_bin_cache_t *) ctx->buf->pos;
                key.len =  h->key_len;

                if (n >= len + (ssize_t) key.len + 1) {
                    ctx->header = h->header;
                    key.data = h->key;

                    small = 0;
                }
            }

        } else {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                          "unknown type of cache file \"%s\"",
                          ctx->file.name.data);
            return NGX_ERROR;
        }

    }

    if (small) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" is to small", ctx->file.name.data);
        return NGX_ERROR;
    }

    if (key.len != ctx->key.len
        || ngx_strncmp(key.data, ctx->key.data, key.len) != 0)
    {
        key.data[key.len] = '\0';
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "md5 collision: \"%s\" and \"%s\"",
                          key.data, ctx->key.data);
        return NGX_DECLINED;
    }

    ctx->header.size = len + key.len + 1;
    ctx->buf->last += n;

    return NGX_OK;
}


int ngx_http_cache_update_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx,
                               ngx_str_t *temp_file)
{
    int        retry;
    ngx_err_t  err;

    retry = 0;

    for ( ;; ) {
        if (ngx_rename_file(temp_file->data, ctx->file.name.data)
                                                             != NGX_FILE_ERROR)
        {
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
