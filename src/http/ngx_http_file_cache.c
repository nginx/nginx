
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif


ngx_int_t ngx_http_file_cache_get(ngx_http_request_t *r,
                                  ngx_http_cache_ctx_t *ctx)
{
    ngx_uint_t         i;
    ngx_str_t         *key;
    ngx_http_cache_t  *c;
    MD5_CTX            md5;

    c = r->cache;

    c->file.name.len = ctx->path->name.len + 1 + ctx->path->len + 32;
    if (!(c->file.name.data = ngx_palloc(r->pool, c->file.name.len + 1))) {
        return NGX_ABORT;
    }

    MD5Init(&md5);

    key = c->key.elts;
    for (i = 0; i < c->key.nelts; i++) {
        MD5Update(&md5, key[i].data, key[i].len);
    }

    MD5Update(&md5, ctx->key.data, ctx->key.len);

    MD5Final(c->md5, &md5);

    ngx_memcpy(c->file.name.data, ctx->path->name.data, ctx->path->name.len);

    ngx_md5_text(c->file.name.data + ctx->path->name.len + 1 + ctx->path->len,
                 c->md5);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "file cache key: %V, md5: %s", &ctx->key,
                  c->file.name.data + ctx->path->name.len + 1 + ctx->path->len);

    ngx_create_hashed_filename(&c->file, ctx->path);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "file cache name: %s", c->file.name.data);

    return ngx_http_file_cache_open(r->cache);
}


ngx_int_t ngx_http_file_cache_open(ngx_http_cache_t *c)
{
    ssize_t                   n;
    ngx_err_t                 err;
    ngx_http_cache_header_t  *h;

    c->file.fd = ngx_open_file(c->file.name.data,
                               NGX_FILE_RDONLY, NGX_FILE_OPEN);

    if (c->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
            return NGX_DECLINED;
        }

        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", c->file.name.data);
        return NGX_ERROR;
    }

    if (c->uniq) {
        if (ngx_fd_info(c->file.fd, &c->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", c->file.name.data);

            return NGX_ERROR;
        }

        if (ngx_file_uniq(&c->file.info) == c->uniq) {
            if (ngx_close_file(c->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              c->file.name.data);
            }

            return NGX_HTTP_CACHE_THE_SAME;
        }
    }

    n = ngx_read_file(&c->file, c->buf->pos, c->buf->end - c->buf->last, 0);

    if (n == NGX_ERROR || n == NGX_AGAIN) {
        return n;
    }

    if (n <= c->header_size) {
        ngx_log_error(NGX_LOG_CRIT, c->log, 0,
                      "cache file \"%s\" is too small", c->file.name.data);
        return NGX_ERROR;
    }

    h = (ngx_http_cache_header_t *) c->buf->pos;
    c->expires = h->expires;
    c->last_modified= h->last_modified;
    c->date = h->date;
    c->length = h->length;

    if (h->key_len > (size_t) (c->buf->end - c->buf->pos)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "cache file \"%s\" is probably invalid",
                      c->file.name.data);
        return NGX_DECLINED;
    }

#if 0

    /* TODO */

    if (c->key_len && h->key_len != c->key_len)  {

        ngx_strncmp(h->key, c->key_data, h->key_len) != 0))

        h->key[h->key_len] = '\0';
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "md5 collision: \"%s\" and \"%s\"",
                          h->key, c->key.data);
        return NGX_DECLINED;
    }

#endif

    c->buf->last += n;

    if (c->expires < ngx_time()) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http file cache expired");
        return NGX_HTTP_CACHE_STALE;
    }

    /* TODO: NGX_HTTP_CACHE_AGED */

    /* STUB */ return NGX_DECLINED;

    return NGX_OK;
}


#if 0


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

#if (NGX_WIN32)
        if (err == NGX_EEXIST) {
            if (ngx_win32_rename_file(temp_file, &ctx->file.name, r->pool)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
#endif

        if (retry || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
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


#endif


ngx_int_t ngx_http_cache_cleaner_handler(ngx_gc_t *gc, ngx_str_t *name,
                                         ngx_dir_t *dir)
{
    int               rc;
    ngx_buf_t         buf;
    ngx_http_cache_t  c;
    u_char            data[sizeof(ngx_http_cache_header_t)];

    ngx_memzero(&c, sizeof(ngx_http_cache_t));

    c.file.fd = NGX_INVALID_FILE;
    c.file.name = *name;
    c.file.log = gc->log;

    c.header_size = sizeof(ngx_http_cache_header_t);
    c.buf = &buf;
    c.log = gc->log;
    c.key_len = 0;

    buf.memory = 1;
    buf.temporary = 1;
    buf.pos = data;
    buf.last = data;
    buf.start = data;
    buf.end = data + sizeof(ngx_http_cache_header_t);

    rc = ngx_http_file_cache_open(&c);

    /* TODO: NGX_AGAIN */

    if (rc != NGX_ERROR&& rc != NGX_DECLINED && rc != NGX_HTTP_CACHE_STALE) {
        return NGX_OK;
    }

    if (ngx_delete_file(name->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, c.log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name->data);
        return NGX_ERROR;
    }

    gc->deleted++;
    gc->freed += ngx_de_size(dir);

    return NGX_OK;
}
