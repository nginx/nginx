
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * The 7 uses before an allocation.
 * We can use maximum 7 bits, i.e up to the 127 uses.
 */
#define NGX_HTTP_CACHE_LAZY_ALLOCATION_BITS  3

typedef struct {
    uint32_t         crc;
    ngx_str_t        key;
    time_t           accessed;

    unsigned         refs:20;    /* 1048576 references */

    unsigned         count:NGX_HTTP_CACHE_LAZY_ALLOCATION_BITS;

    unsigned         deleted:1;
    unsigned         expired:1;
    unsigned         memory:1;
    unsigned         mmap:1;
    unsigned         notify:1;

    ngx_fd_t         fd;
#if (NGX_USE_HTTP_FILE_CACHE_UNIQ)
    ngx_file_uniq_t  uniq;       /* no needed with kqueue */
#endif
    time_t           last_modified;
    time_t           updated;

    union {
        off_t        size;
        ngx_str_t    value;
    } data;
} ngx_http_cache_t;


typedef struct {
    time_t       expires;
    time_t       last_modified;
    time_t       date;
    off_t        length;
    size_t       key_len;
    char         key[1];
} ngx_http_cache_header_t;


#define NGX_HTTP_CACHE_HASH   7
#define NGX_HTTP_CACHE_NELTS  4

typedef struct {
    ngx_http_cache_t         *elts;
    size_t                    hash;
    size_t                    nelts;
    time_t                    life;
    time_t                    update;
#if (NGX_THREADS)
    ngx_mutex_t               mutex;
#endif
    ngx_pool_t               *pool;
} ngx_http_cache_hash_t;


typedef struct {
    ngx_http_cache_hash_t    *hash;
    ngx_http_cache_t         *cache;
    ngx_file_t                file;
    ngx_str_t                 key;
    uint32_t                  crc;
    u_char                    md5[16];
    ngx_path_t               *path;
    ngx_buf_t                *buf;
    time_t                    expires;
    time_t                    last_modified;
    time_t                    date;
    off_t                     length;
    ssize_t                   header_size;
    size_t                    file_start;
    ngx_log_t                *log;
} ngx_http_cache_ctx_t;



#define NGX_HTTP_CACHE_STALE     1
#define NGX_HTTP_CACHE_AGED      2
#define NGX_HTTP_CACHE_THE_SAME  3


ngx_http_cache_t *ngx_http_cache_get(ngx_http_cache_hash_t *cache,
                                     ngx_http_cleanup_t *cleanup,
                                     ngx_str_t *key, uint32_t *crc);

ngx_http_cache_t *ngx_http_cache_alloc(ngx_http_cache_hash_t *hash,
                                       ngx_http_cache_t *cache,
                                       ngx_http_cleanup_t *cleanup,
                                       ngx_str_t *key, uint32_t crc,
                                       ngx_str_t *value, ngx_log_t *log);
void ngx_http_cache_free(ngx_http_cache_t *cache,
                         ngx_str_t *key, ngx_str_t *value, ngx_log_t *log);
void ngx_http_cache_lock(ngx_http_cache_hash_t *hash, ngx_http_cache_t *cache);
void ngx_http_cache_unlock(ngx_http_cache_hash_t *hash,
                           ngx_http_cache_t *cache, ngx_log_t *log);

int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx);
int ngx_http_cache_open_file(ngx_http_cache_ctx_t *ctx, ngx_file_uniq_t uniq);
int ngx_http_cache_update_file(ngx_http_request_t *r,ngx_http_cache_ctx_t *ctx,
                               ngx_str_t *temp_file);

int ngx_http_send_cached(ngx_http_request_t *r);


int ngx_garbage_collector_http_cache_handler(ngx_gc_t *gc, ngx_str_t *name,
                                             ngx_dir_t *dir);

char *ngx_http_set_cache_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
